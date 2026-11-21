package com.example.vpn

import com.example.vpn.protocol.WorkerTunnelSession
import com.example.vpn.protocol.WorkerWebSocketClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

data class TcpFlowKey(
    val srcIp: Int,
    val srcPort: Int,
    val dstIp: Int,
    val dstPort: Int
)

/**
 * Pure-Kotlin user-space TCP flow manager bridging TUN IPv4/TCP packets to per-flow
 * Worker WebSocket tunnels with optional TLS SNI / HTTP Host sniffing.
 */
class TcpSessionManager(
    private val scope: CoroutineScope,
    private val wsClient: WorkerWebSocketClient,
    private val sniSniffingEnabled: Boolean,
    private val lookupDomain: (Int) -> String?,
    private val writePacketToTun: (ByteArray) -> Unit,
    private val onBytesSent: (Int) -> Unit,
    private val onBytesReceived: (Int) -> Unit
) {
    companion object {
        private const val MSS = 1360
        private const val IDLE_TIMEOUT_MS = 90_000L
        private const val SNI_WAIT_TIMEOUT_MS = 220L
    }

    private val sessions = ConcurrentHashMap<TcpFlowKey, TcpFlowSession>()
    private val activeTunnelCounter = AtomicInteger(0)

    val activeSessionCount: Int
        get() = activeTunnelCounter.get().coerceAtLeast(0)

    private val reaperJob: Job = scope.launch(Dispatchers.IO) {
        while (isActive) {
            delay(15_000L)
            val now = System.currentTimeMillis()
            val iterator = sessions.entries.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                if (now - entry.value.lastActivityMs.get() > IDLE_TIMEOUT_MS) {
                    iterator.remove()
                    entry.value.close(sendReset = false)
                }
            }
        }
    }

    fun handleTcpPacket(
        ip: PacketUtils.Ipv4Header,
        tcp: PacketUtils.TcpHeader,
        rawPacket: ByteArray
    ) {
        val key = TcpFlowKey(ip.srcIp, tcp.srcPort, ip.dstIp, tcp.dstPort)
        val isSyn = (tcp.flags and PacketUtils.TCP_SYN) != 0
        val isAck = (tcp.flags and PacketUtils.TCP_ACK) != 0
        val isRst = (tcp.flags and PacketUtils.TCP_RST) != 0
        val isFin = (tcp.flags and PacketUtils.TCP_FIN) != 0

        if (isRst) {
            sessions.remove(key)?.close(sendReset = false)
            return
        }

        if (isSyn && !isAck) {
            sessions.remove(key)?.close(sendReset = false)
            val session = TcpFlowSession(key = key, initialClientSeq = tcp.seqNum)
            sessions[key] = session
            session.onSynReceived()
            return
        }

        val session = sessions[key]
        if (session == null) {
            // Unknown flow: politely reply with RST so client retries cleanly
            if (!isFin) {
                val rst = PacketUtils.buildIpv4TcpPacket(
                    srcIp = ip.dstIp,
                    dstIp = ip.srcIp,
                    srcPort = tcp.dstPort,
                    dstPort = tcp.srcPort,
                    seqNum = tcp.ackNum,
                    ackNum = (tcp.seqNum + tcp.payloadLength + if (isFin) 1 else 0) and 0xFFFFFFFFL,
                    flags = PacketUtils.TCP_RST or PacketUtils.TCP_ACK
                )
                writePacketToTun(rst)
            }
            return
        }

        session.lastActivityMs.set(System.currentTimeMillis())

        if (tcp.payloadLength > 0) {
            val payload = rawPacket.copyOfRange(tcp.payloadOffset, tcp.payloadOffset + tcp.payloadLength)
            session.onClientData(tcp.seqNum, payload)
        }

        if (isFin) {
            session.onClientFin(tcp.seqNum, tcp.payloadLength)
        }
    }

    fun closeAll() {
        reaperJob.cancel()
        val all = sessions.values.toList()
        sessions.clear()
        for (session in all) {
            session.close(sendReset = false)
        }
    }

    private inner class TcpFlowSession(
        private val key: TcpFlowKey,
        initialClientSeq: Long
    ) {
        private val lock = Any()
        private var clientNextSeq: Long = (initialClientSeq + 1L) and 0xFFFFFFFFL
        private var serverNextSeq: Long = Random.nextInt(100_000, Int.MAX_VALUE).toLong() and 0xFFFFFFFFL
        private var tunnelSession: WorkerTunnelSession? = null
        private var dialStarted = false
        private var closed = false
        private var sniWaitJob: Job? = null
        val lastActivityMs = AtomicLong(System.currentTimeMillis())

        fun onSynReceived() {
            // Immediately send SYN-ACK to local stack
            val synAck = PacketUtils.buildIpv4TcpPacket(
                srcIp = key.dstIp,
                dstIp = key.srcIp,
                srcPort = key.dstPort,
                dstPort = key.srcPort,
                seqNum = serverNextSeq,
                ackNum = clientNextSeq,
                flags = PacketUtils.TCP_SYN or PacketUtils.TCP_ACK
            )
            serverNextSeq = (serverNextSeq + 1L) and 0xFFFFFFFFL
            writePacketToTun(synAck)

            val cachedDomain = lookupDomain(key.dstIp)
            val shouldSniff = sniSniffingEnabled &&
                cachedDomain == null &&
                (key.dstPort == 443 || key.dstPort == 80 || key.dstPort == 8443 || key.dstPort == 8080)

            if (!shouldSniff) {
                startWorkerDial(cachedDomain ?: PacketUtils.ipIntToString(key.dstIp), initialPayload = null)
            } else {
                // Wait briefly for TLS ClientHello / HTTP Host so we can pass the real domain to Worker
                sniWaitJob = scope.launch(Dispatchers.IO) {
                    delay(SNI_WAIT_TIMEOUT_MS)
                    startWorkerDial(PacketUtils.ipIntToString(key.dstIp), initialPayload = null)
                }
            }
        }

        fun onClientData(seqNum: Long, payload: ByteArray) {
            var toForward: ByteArray? = null
            synchronized(lock) {
                if (closed) return
                // Handle duplicate/retransmitted segments cleanly
                val diff = ((seqNum - clientNextSeq) and 0xFFFFFFFFL)
                if (diff != 0L) {
                    // Retransmission or out-of-order: re-ACK expected clientNextSeq
                    sendAckOnlyLocked()
                    return
                }
                clientNextSeq = (clientNextSeq + payload.size.toLong()) and 0xFFFFFFFFL
                sendAckOnlyLocked()
                toForward = payload
            }

            val data = toForward ?: return
            if (!dialStarted) {
                val sniffedHost = if (sniSniffingEnabled) {
                    PacketUtils.extractTlsSni(data) ?: PacketUtils.extractHttpHost(data)
                } else null
                val targetHost = sniffedHost ?: lookupDomain(key.dstIp) ?: PacketUtils.ipIntToString(key.dstIp)
                startWorkerDial(targetHost, initialPayload = data)
            } else {
                tunnelSession?.send(data)
            }
        }

        fun onClientFin(seqNum: Long, payloadLen: Int) {
            synchronized(lock) {
                if (closed) return
                val expectedEnd = (seqNum + payloadLen.toLong() + 1L) and 0xFFFFFFFFL
                clientNextSeq = expectedEnd
                sendAckOnlyLocked()
            }
            sessions.remove(key)
            close(sendReset = false, sendFin = true)
        }

        private fun startWorkerDial(targetHost: String, initialPayload: ByteArray?) {
            synchronized(lock) {
                if (dialStarted || closed) {
                    if (initialPayload != null && !closed) {
                        tunnelSession?.send(initialPayload)
                    }
                    return
                }
                dialStarted = true
                sniWaitJob?.cancel()
                sniWaitJob = null
            }

            activeTunnelCounter.incrementAndGet()
            val wsSession = wsClient.openTunnel(
                targetHost = targetHost,
                targetPort = key.dstPort,
                onReady = {},
                onData = { remoteBytes ->
                    lastActivityMs.set(System.currentTimeMillis())
                    sendRemoteDataToTun(remoteBytes)
                },
                onClosed = { errorReason ->
                    sessions.remove(key)
                    close(sendReset = errorReason != null, sendFin = errorReason == null)
                },
                onBytesSent = onBytesSent,
                onBytesReceived = onBytesReceived
            )

            synchronized(lock) {
                if (closed) {
                    wsSession.close()
                    return
                }
                tunnelSession = wsSession
            }

            if (initialPayload != null && initialPayload.isNotEmpty()) {
                wsSession.send(initialPayload)
            }
        }

        private fun sendRemoteDataToTun(data: ByteArray) {
            synchronized(lock) {
                if (closed) return
                var offset = 0
                while (offset < data.size) {
                    val chunkSize = (data.size - offset).coerceAtMost(MSS)
                    val isLast = offset + chunkSize >= data.size
                    val flags = PacketUtils.TCP_ACK or if (isLast) PacketUtils.TCP_PSH else 0
                    val packet = PacketUtils.buildIpv4TcpPacket(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seqNum = serverNextSeq,
                        ackNum = clientNextSeq,
                        flags = flags,
                        payload = data,
                        payloadOffset = offset,
                        payloadLength = chunkSize
                    )
                    serverNextSeq = (serverNextSeq + chunkSize.toLong()) and 0xFFFFFFFFL
                    writePacketToTun(packet)
                    offset += chunkSize
                }
            }
        }

        private fun sendAckOnlyLocked() {
            val ackPacket = PacketUtils.buildIpv4TcpPacket(
                srcIp = key.dstIp,
                dstIp = key.srcIp,
                srcPort = key.dstPort,
                dstPort = key.srcPort,
                seqNum = serverNextSeq,
                ackNum = clientNextSeq,
                flags = PacketUtils.TCP_ACK
            )
            writePacketToTun(ackPacket)
        }

        fun close(sendReset: Boolean, sendFin: Boolean = false) {
            val wsToClose: WorkerTunnelSession?
            val wasDialed: Boolean
            synchronized(lock) {
                if (closed) return
                closed = true
                sniWaitJob?.cancel()
                sniWaitJob = null
                wsToClose = tunnelSession
                tunnelSession = null
                wasDialed = dialStarted

                if (sendReset) {
                    val rst = PacketUtils.buildIpv4TcpPacket(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seqNum = serverNextSeq,
                        ackNum = clientNextSeq,
                        flags = PacketUtils.TCP_RST or PacketUtils.TCP_ACK
                    )
                    writePacketToTun(rst)
                } else if (sendFin) {
                    val fin = PacketUtils.buildIpv4TcpPacket(
                        srcIp = key.dstIp,
                        dstIp = key.srcIp,
                        srcPort = key.dstPort,
                        dstPort = key.srcPort,
                        seqNum = serverNextSeq,
                        ackNum = clientNextSeq,
                        flags = PacketUtils.TCP_FIN or PacketUtils.TCP_ACK
                    )
                    serverNextSeq = (serverNextSeq + 1L) and 0xFFFFFFFFL
                    writePacketToTun(fin)
                }
            }
            if (wasDialed) {
                activeTunnelCounter.decrementAndGet()
            }
            wsToClose?.close()
        }
    }
}
