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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * High-speed multi-mode DNS engine for the VPN TUN interface:
 * 1. Fake DNS (when enabled): <0.1ms synthetic 198.18.0.0/15 A-record replies with zero network RTT!
 *    TcpSessionManager resolves the fake IP back to the real domain and dials Worker natively.
 * 2. Local DNS (when enabled): In-app TTL-cached resolver using HTTP/2 DoH over port 443
 *    (Cloudflare DoH via Clean IP -> Google DoH fallback -> persistent Worker TCP DNS fallback),
 *    completely immune to Worker port-53 restrictions.
 * 3. Instant empty NOERROR for AAAA (Type 28) & HTTPS/SVCB (Type 65) on IPv4 TUN.
 */
class DnsProxyHandler(
    private val scope: CoroutineScope,
    private val wsClient: WorkerWebSocketClient,
    private val fakeDnsEnabled: Boolean,
    private val localDnsEnabled: Boolean,
    private val writePacketToTun: (ByteArray) -> Unit,
    private val onBytesSent: (Int) -> Unit,
    private val onBytesReceived: (Int) -> Unit
) {
    private data class CacheKey(val domain: String, val qtype: Int)
    private data class CachedAnswer(val wireResponse: ByteArray, val expiresAtMs: Long)
    private data class ParsedQuestion(val domain: String, val qtype: Int, val questionEndOffset: Int)

    private val fakeDnsPool = FakeDnsPool(maxEntries = 4096)
    private val upstreamServers = listOf("8.8.8.8", "8.8.4.4", "9.9.9.9")
    private val serverRotation = AtomicInteger(0)
    private val muxTxIdGenerator = AtomicInteger(1)

    private val ipToDomainCache: MutableMap<Int, String> = Collections.synchronizedMap(
        object : LinkedHashMap<Int, String>(256, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, String>?): Boolean = size > 1024
        }
    )

    private val dnsResponseCache: MutableMap<CacheKey, CachedAnswer> = Collections.synchronizedMap(
        object : LinkedHashMap<CacheKey, CachedAnswer>(256, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<CacheKey, CachedAnswer>?): Boolean = size > 512
        }
    )

    private val inFlightDedup = ConcurrentHashMap<CacheKey, CompletableDeferred<ByteArray?>>()

    private val tunnelLock = Any()
    private var persistentTunnel: WorkerTunnelSession? = null
    private val streamBuffer = ByteArrayOutputStream()
    private val pendingMuxQueries = ConcurrentHashMap<Int, CompletableDeferred<ByteArray?>>()

    @Volatile
    private var closed = false

    fun prewarm() {
        if (!fakeDnsEnabled && !localDnsEnabled) {
            scope.launch(Dispatchers.IO) { ensurePersistentTunnel() }
        }
    }

    fun lookupDomainForIp(ip: Int): String? {
        if (fakeDnsEnabled) {
            fakeDnsPool.lookupDomain(ip)?.let { return it }
        }
        return ipToDomainCache[ip]
    }

    fun handleUdpDnsPacket(
        ip: PacketUtils.Ipv4Header,
        udp: PacketUtils.UdpHeader,
        rawPacket: ByteArray
    ) {
        if (closed || udp.payloadLength < 12) return
        val dnsQuery = rawPacket.copyOfRange(udp.payloadOffset, udp.payloadOffset + udp.payloadLength)
        val question = parseQuestion(dnsQuery)

        // 1) IPv4-only TUN: instantly suppress AAAA (28) & HTTPS/SVCB (65) to stop IPv6/QUIC stalls
        if (question != null && (question.qtype == 28 || question.qtype == 65)) {
            sendUdpReply(ip, udp, buildEmptyNoErrorResponse(dnsQuery, question.questionEndOffset))
            return
        }

        // 2) Fake DNS fast-path: <0.1ms synthetic 198.18.x.y answer for IPv4 A (Type 1) queries!
        if (fakeDnsEnabled && question != null && question.qtype == 1) {
            val fakeIp = fakeDnsPool.allocateOrGet(question.domain)
            val fakeResponse = buildFakeAResponse(dnsQuery, question.questionEndOffset, fakeIp)
            sendUdpReply(ip, udp, fakeResponse)
            return
        }

        // 3) TTL-aware cache hit (<0.5ms)
        if (question != null) {
            val cacheKey = CacheKey(question.domain.lowercase(), question.qtype)
            val cached = dnsResponseCache[cacheKey]
            if (cached != null && System.currentTimeMillis() < cached.expiresAtMs) {
                val reply = cached.wireResponse.copyOf()
                reply[0] = dnsQuery[0]
                reply[1] = dnsQuery[1]
                sendUdpReply(ip, udp, reply)
                return
            }
        }

        scope.launch(Dispatchers.IO) {
            val response = if (question != null) {
                resolveWithDeduplication(dnsQuery, question)
            } else {
                resolveUpstream(dnsQuery)
            } ?: return@launch

            if (question != null && question.qtype == 1) {
                cacheARecords(response, question.domain)
            }
            val finalReply = response.copyOf()
            if (finalReply.size >= 2) {
                finalReply[0] = dnsQuery[0]
                finalReply[1] = dnsQuery[1]
            }
            sendUdpReply(ip, udp, finalReply)
        }
    }

    private suspend fun resolveWithDeduplication(
        dnsQuery: ByteArray,
        question: ParsedQuestion
    ): ByteArray? {
        val cacheKey = CacheKey(question.domain.lowercase(), question.qtype)
        val existing = inFlightDedup[cacheKey]
        if (existing != null) return existing.await()

        val mine = CompletableDeferred<ByteArray?>()
        val raced = inFlightDedup.putIfAbsent(cacheKey, mine)
        if (raced != null) return raced.await()

        return try {
            val result = resolveUpstream(dnsQuery)
            if (result != null && result.size >= 12) {
                val rcode = result[3].toInt() and 0x0F
                if (rcode == 0) {
                    val ttlSec = extractMinTtlSeconds(result).coerceIn(30L, 600L)
                    dnsResponseCache[cacheKey] = CachedAnswer(
                        wireResponse = result,
                        expiresAtMs = System.currentTimeMillis() + ttlSec * 1000L
                    )
                }
            }
            mine.complete(result)
            result
        } catch (_: Exception) {
            mine.complete(null)
            null
        } finally {
            inFlightDedup.remove(cacheKey, mine)
        }
    }

    private suspend fun resolveUpstream(dnsQuery: ByteArray): ByteArray? {
        // When Local DNS is enabled, resolve via fast HTTP/2 DoH on port 443 first (immune to port 53 blocks!)
        if (localDnsEnabled) {
            val dohResp = wsClient.queryLocalDoh(dnsQuery)
            if (dohResp != null) {
                onBytesSent(dnsQuery.size)
                onBytesReceived(dohResp.size)
                return dohResp
            }
        }

        // Fallback / Remote Worker TCP DNS (8.8.8.8:53)
        val firstTry = queryOverPersistentTunnel(dnsQuery, timeoutMs = 2_500L)
        if (firstTry != null) return firstTry

        resetPersistentTunnel()
        return queryOverPersistentTunnel(dnsQuery, timeoutMs = 3_500L)
    }

    private suspend fun queryOverPersistentTunnel(dnsQuery: ByteArray, timeoutMs: Long): ByteArray? {
        if (closed || dnsQuery.size < 12) return null
        val tunnel = ensurePersistentTunnel() ?: return null

        val muxId = muxTxIdGenerator.getAndIncrement() and 0xFFFF
        val deferred = CompletableDeferred<ByteArray?>()
        pendingMuxQueries[muxId] = deferred

        val framed = ByteArray(2 + dnsQuery.size)
        framed[0] = ((dnsQuery.size ushr 8) and 0xFF).toByte()
        framed[1] = (dnsQuery.size and 0xFF).toByte()
        System.arraycopy(dnsQuery, 0, framed, 2, dnsQuery.size)
        framed[2] = ((muxId ushr 8) and 0xFF).toByte()
        framed[3] = (muxId and 0xFF).toByte()

        if (!tunnel.send(framed)) {
            pendingMuxQueries.remove(muxId)
            resetPersistentTunnel()
            return null
        }

        return try {
            withTimeoutOrNull(timeoutMs) { deferred.await() }
        } finally {
            pendingMuxQueries.remove(muxId)
        }
    }

    private fun ensurePersistentTunnel(): WorkerTunnelSession? {
        synchronized(tunnelLock) {
            if (closed) return null
            val existing = persistentTunnel
            if (existing != null) return existing

            streamBuffer.reset()
            val serverIp = upstreamServers[Math.floorMod(serverRotation.getAndIncrement(), upstreamServers.size)]
            lateinit var created: WorkerTunnelSession
            created = wsClient.openTunnel(
                targetHost = serverIp,
                targetPort = 53,
                onReady = {},
                onData = { chunk -> handlePersistentStreamData(created, chunk) },
                onClosed = { handlePersistentTunnelClosed(created) },
                onBytesSent = onBytesSent,
                onBytesReceived = onBytesReceived
            )
            persistentTunnel = created
            return created
        }
    }

    private fun handlePersistentStreamData(source: WorkerTunnelSession, chunk: ByteArray) {
        val completedFrames = mutableListOf<ByteArray>()
        synchronized(tunnelLock) {
            if (persistentTunnel !== source) return
            streamBuffer.write(chunk)
            val bytes = streamBuffer.toByteArray()
            var offset = 0
            while (offset + 2 <= bytes.size) {
                val frameLen = PacketUtils.readUInt16(bytes, offset)
                if (frameLen == 0) {
                    offset += 2
                    continue
                }
                if (offset + 2 + frameLen > bytes.size) break
                completedFrames.add(bytes.copyOfRange(offset + 2, offset + 2 + frameLen))
                offset += 2 + frameLen
            }
            if (offset > 0) {
                streamBuffer.reset()
                if (offset < bytes.size) {
                    streamBuffer.write(bytes, offset, bytes.size - offset)
                }
            }
        }

        for (frame in completedFrames) {
            if (frame.size >= 2) {
                val muxId = PacketUtils.readUInt16(frame, 0)
                pendingMuxQueries.remove(muxId)?.complete(frame)
            }
        }
    }

    private fun handlePersistentTunnelClosed(source: WorkerTunnelSession) {
        synchronized(tunnelLock) {
            if (persistentTunnel !== source) return
            persistentTunnel = null
            streamBuffer.reset()
        }
        val iterator = pendingMuxQueries.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            iterator.remove()
            entry.value.complete(null)
        }
    }

    private fun resetPersistentTunnel() {
        val toClose: WorkerTunnelSession?
        synchronized(tunnelLock) {
            toClose = persistentTunnel
            persistentTunnel = null
            streamBuffer.reset()
        }
        toClose?.close()
    }

    fun close() {
        closed = true
        resetPersistentTunnel()
        fakeDnsPool.clear()
        pendingMuxQueries.values.forEach { it.complete(null) }
        pendingMuxQueries.clear()
        inFlightDedup.values.forEach { it.complete(null) }
        inFlightDedup.clear()
    }

    private fun sendUdpReply(
        ip: PacketUtils.Ipv4Header,
        udp: PacketUtils.UdpHeader,
        dnsPayload: ByteArray
    ) {
        val responsePacket = PacketUtils.buildIpv4UdpPacket(
            srcIp = ip.dstIp,
            dstIp = ip.srcIp,
            srcPort = udp.dstPort,
            dstPort = udp.srcPort,
            payload = dnsPayload
        )
        writePacketToTun(responsePacket)
    }

    /**
     * Constructs a valid RFC 1035 DNS A-record response pointing to the allocated Fake IPv4
     * with short TTL (10s) so apps never persist synthetic IPs after VPN disconnect.
     */
    private fun buildFakeAResponse(query: ByteArray, questionEndOffset: Int, fakeIp: Int): ByteArray {
        val qEnd = questionEndOffset.coerceIn(12, query.size)
        val out = ByteArray(qEnd + 16)
        System.arraycopy(query, 0, out, 0, qEnd)

        val rd = query[2].toInt() and 0x01
        out[2] = (0x80 or rd).toByte() // QR=1, preserve RD
        out[3] = 0x80.toByte()         // RA=1, RCODE=0 (NOERROR)
        // QDCOUNT = 1, ANCOUNT = 1, NSCOUNT = 0, ARCOUNT = 0
        out[4] = 0; out[5] = 1
        out[6] = 0; out[7] = 1
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0

        // Answer RR: pointer to offset 12 (0xC00C), Type A (1), Class IN (1), TTL 10s, RDLENGTH 4, IPv4
        var p = qEnd
        out[p++] = 0xC0.toByte(); out[p++] = 0x0C.toByte()
        out[p++] = 0x00; out[p++] = 0x01 // Type A
        out[p++] = 0x00; out[p++] = 0x01 // Class IN
        out[p++] = 0x00; out[p++] = 0x00; out[p++] = 0x00; out[p++] = 10 // TTL = 10s
        out[p++] = 0x00; out[p++] = 0x04 // RDLENGTH = 4
        out[p++] = ((fakeIp ushr 24) and 0xFF).toByte()
        out[p++] = ((fakeIp ushr 16) and 0xFF).toByte()
        out[p++] = ((fakeIp ushr 8) and 0xFF).toByte()
        out[p] = (fakeIp and 0xFF).toByte()
        return out
    }

    private fun buildEmptyNoErrorResponse(query: ByteArray, questionEndOffset: Int): ByteArray {
        val qEnd = questionEndOffset.coerceIn(12, query.size)
        val out = ByteArray(qEnd)
        System.arraycopy(query, 0, out, 0, qEnd)
        val rd = query[2].toInt() and 0x01
        out[2] = (0x80 or rd).toByte()
        out[3] = 0x80.toByte()
        out[4] = 0; out[5] = 1
        out[6] = 0; out[7] = 0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        return out
    }

    private fun parseQuestion(dns: ByteArray): ParsedQuestion? {
        if (dns.size < 17) return null
        val labels = mutableListOf<String>()
        var pos = 12
        while (pos < dns.size) {
            val len = dns[pos].toInt() and 0xFF
            if (len == 0) {
                pos++
                break
            }
            if ((len and 0xC0) != 0) return null
            pos++
            if (pos + len > dns.size) return null
            labels.add(String(dns, pos, len, Charsets.US_ASCII))
            pos += len
        }
        if (labels.isEmpty() || pos + 4 > dns.size) return null
        val qtype = PacketUtils.readUInt16(dns, pos)
        return ParsedQuestion(
            domain = labels.joinToString("."),
            qtype = qtype,
            questionEndOffset = pos + 4
        )
    }

    private fun cacheARecords(dns: ByteArray, queriedDomain: String) {
        if (dns.size < 12) return
        val qdCount = PacketUtils.readUInt16(dns, 4)
        val anCount = PacketUtils.readUInt16(dns, 6)
        var pos = 12

        repeat(qdCount) {
            pos = skipDnsName(dns, pos)
            if (pos < 0 || pos + 4 > dns.size) return
            pos += 4
        }

        repeat(anCount) {
            pos = skipDnsName(dns, pos)
            if (pos < 0 || pos + 10 > dns.size) return
            val type = PacketUtils.readUInt16(dns, pos)
            val rdLength = PacketUtils.readUInt16(dns, pos + 8)
            pos += 10
            if (pos + rdLength > dns.size) return
            if (type == 1 && rdLength == 4) {
                val ipInt = PacketUtils.ipv4BytesToInt(dns, pos)
                ipToDomainCache[ipInt] = queriedDomain
            }
            pos += rdLength
        }
    }

    private fun extractMinTtlSeconds(dns: ByteArray): Long {
        if (dns.size < 12) return 60L
        val qdCount = PacketUtils.readUInt16(dns, 4)
        val anCount = PacketUtils.readUInt16(dns, 6)
        var pos = 12
        repeat(qdCount) {
            pos = skipDnsName(dns, pos)
            if (pos < 0 || pos + 4 > dns.size) return 60L
            pos += 4
        }
        var minTtl = Long.MAX_VALUE
        repeat(anCount) {
            pos = skipDnsName(dns, pos)
            if (pos < 0 || pos + 10 > dns.size) return if (minTtl == Long.MAX_VALUE) 60L else minTtl
            val ttl = PacketUtils.readUInt32(dns, pos + 4)
            val rdLength = PacketUtils.readUInt16(dns, pos + 8)
            if (ttl in 1..86400 && ttl < minTtl) minTtl = ttl
            pos += 10 + rdLength
            if (pos > dns.size) return if (minTtl == Long.MAX_VALUE) 60L else minTtl
        }
        return if (minTtl == Long.MAX_VALUE) 60L else minTtl
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
