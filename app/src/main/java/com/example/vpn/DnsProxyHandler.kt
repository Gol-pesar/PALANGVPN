package com.example.vpn

import com.example.vpn.protocol.WorkerTunnelSession
import com.example.vpn.protocol.WorkerWebSocketClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.util.Collections

/**
 * Intercepts UDP port 53 DNS packets from the TUN interface and resolves them securely
 * via TCP DNS (RFC 1035) to 1.1.1.1:53 through the Worker WebSocket tunnel.
 * Also caches IPv4 -> Domain mappings so subsequent TCP connections send real hostnames.
 */
class DnsProxyHandler(
    private val scope: CoroutineScope,
    private val wsClient: WorkerWebSocketClient,
    private val writePacketToTun: (ByteArray) -> Unit,
    private val onBytesSent: (Int) -> Unit,
    private val onBytesReceived: (Int) -> Unit
) {
    private val ipToDomainCache: MutableMap<Int, String> = Collections.synchronizedMap(
        object : LinkedHashMap<Int, String>(256, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, String>?): Boolean {
                return size > 1024
            }
        }
    )

    fun lookupDomainForIp(ip: Int): String? = ipToDomainCache[ip]

    fun handleUdpDnsPacket(
        ip: PacketUtils.Ipv4Header,
        udp: PacketUtils.UdpHeader,
        rawPacket: ByteArray
    ) {
        if (udp.payloadLength < 12) return
        val dnsQuery = rawPacket.copyOfRange(udp.payloadOffset, udp.payloadOffset + udp.payloadLength)
        val queriedDomain = parseQueryDomain(dnsQuery)

        scope.launch(Dispatchers.IO) {
            val dnsResponse = resolveOverWorkerTcpDns(dnsQuery) ?: return@launch
            if (queriedDomain != null) {
                cacheARecords(dnsResponse, queriedDomain)
            }
            val responsePacket = PacketUtils.buildIpv4UdpPacket(
                srcIp = ip.dstIp,
                dstIp = ip.srcIp,
                srcPort = udp.dstPort,
                dstPort = udp.srcPort,
                payload = dnsResponse
            )
            writePacketToTun(responsePacket)
        }
    }

    private suspend fun resolveOverWorkerTcpDns(dnsQuery: ByteArray): ByteArray? {
        val deferred = CompletableDeferred<ByteArray?>()
        val accumulator = ByteArrayOutputStream()
        var expectedLen = -1

        var session: WorkerTunnelSession? = null
        try {
            // RFC 1035 TCP DNS framing: 2-byte big-endian length prefix + wire query
            val framedQuery = ByteArray(2 + dnsQuery.size)
            framedQuery[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
            framedQuery[1] = (dnsQuery.size and 0xFF).toByte()
            System.arraycopy(dnsQuery, 0, framedQuery, 2, dnsQuery.size)

            session = wsClient.openTunnel(
                targetHost = "1.1.1.1",
                targetPort = 53,
                onReady = {},
                onData = { chunk ->
                    synchronized(accumulator) {
                        if (deferred.isCompleted) return@synchronized
                        accumulator.write(chunk)
                        val bytes = accumulator.toByteArray()
                        if (expectedLen < 0 && bytes.size >= 2) {
                            expectedLen = PacketUtils.readUInt16(bytes, 0)
                        }
                        if (expectedLen > 0 && bytes.size >= 2 + expectedLen) {
                            deferred.complete(bytes.copyOfRange(2, 2 + expectedLen))
                        }
                    }
                },
                onClosed = {
                    if (!deferred.isCompleted) deferred.complete(null)
                },
                onBytesSent = onBytesSent,
                onBytesReceived = onBytesReceived
            )
            session.send(framedQuery)
            return withTimeoutOrNull(6_000L) { deferred.await() }
        } catch (_: Exception) {
            return null
        } finally {
            session?.close()
        }
    }

    private fun parseQueryDomain(dns: ByteArray): String? {
        if (dns.size < 13) return null
        val labels = mutableListOf<String>()
        var pos = 12
        while (pos < dns.size) {
            val len = dns[pos].toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) != 0) break
            pos++
            if (pos + len > dns.size) return null
            labels.add(String(dns, pos, len, Charsets.US_ASCII))
            pos += len
        }
        return if (labels.isNotEmpty()) labels.joinToString(".") else null
    }

    private fun cacheARecords(dns: ByteArray, queriedDomain: String) {
        if (dns.size < 12) return
        val qdCount = PacketUtils.readUInt16(dns, 4)
        val anCount = PacketUtils.readUInt16(dns, 6)
        var pos = 12

        // Skip questions
        repeat(qdCount) {
            pos = skipDnsName(dns, pos)
            if (pos < 0 || pos + 4 > dns.size) return
            pos += 4
        }

        // Read answer A records
        repeat(anCount) {
            pos = skipDnsName(dns, pos)
            if (pos < 0 || pos + 10 > dns.size) return
            val type = PacketUtils.readUInt16(dns, pos)
            val rdLength = PacketUtils.readUInt16(dns, pos + 8)
            pos += 10
            if (pos + rdLength > dns.size) return
            if (type == 1 && rdLength == 4) { // Type A (IPv4)
                val ipInt = PacketUtils.ipv4BytesToInt(dns, pos)
                ipToDomainCache[ipInt] = queriedDomain
            }
            pos += rdLength
        }
    }

    private fun skipDnsName(dns: ByteArray, start: Int): Int {
        var pos = start
        var steps = 0
        while (pos < dns.size && steps < 128) {
            val len = dns[pos].toInt() and 0xFF
            if (len == 0) return pos + 1
            if ((len and 0xC0) == 0xC0) return pos + 2
            pos += 1 + len
            steps++
        }
        return -1
    }
}
