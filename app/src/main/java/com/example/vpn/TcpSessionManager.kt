package com.example.vpn

import com.example.vpn.protocol.WorkerTunnelSession
import com.example.vpn.protocol.WorkerWebSocketClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.ByteArrayOutputStream
import java.util.ArrayDeque
import java.util.TreeMap
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
 * Reliable, high-throughput user-space TCP engine bridging Android TUN IPv4/TCP flows
 * to Worker WebSocket tunnels.
 *
 * Key reliability & speed features:
 * - RFC 7323 Window Scaling & MSS (1360) negotiation on SYN-ACK
 * - Sliding-window flow control respecting client advertised window (prevents TUN overflow drops)
 * - Unacknowledged segment queue with 3-dup-ACK Fast Retransmit and RTO timer (eliminates stalls)
 * - Out-of-order client segment reassembly & contiguous coalescing (fewer WebSocket frames)
 * - Zero-delay eager Worker dialing whenever DNS cache already knows the destination domain
 * - Clean half-close handling so trailing response bytes flush before FIN-ACK
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
        private const val DEFAULT_MSS = PacketUtils.DEFAULT_MSS
        private const val MAX_IN_FLIGHT_BYTES = 196_608 // 192 KB sliding window cap
        private const val IDLE_TIMEOUT_MS = 90_000L
        private const val SNI_WAIT_TIMEOUT_MS = 80L
        private const val RETRANSMIT_TICK_MS = 120L
        private const val BASE_RTO_MS = 300L
        private const val MAX_RTO_MS = 2_400L
        private const val MAX_RETRIES = 8
        private const val MAX_OOO_SEGMENTS = 32
    }

    private data class SentSegment(
        val seqStart: Long,
        val seqEnd: Long,
        val payload: ByteArray,
        val flags: Int,
        var sentAtMs: Long,
        var retries: Int = 0
    )

    private val sessions = ConcurrentHashMap<TcpFlowKey, TcpFlowSession>()
    private val activeTunnelCounter = AtomicInteger(0)

    val activeSessionCount: Int
        get() = activeTunnelCounter.get().coerceAtLeast(0)

    private val maintenanceJob: Job = scope.launch(Dispatchers.IO) {
        var idleTickCounter = 0
        while (isActive) {
            delay(RETRANSMIT_TICK_MS)
            val now = System.currentTimeMillis()
            idleTickCounter++
            val checkIdle = idleTickCounter >= 120 // ~15 seconds

            val iterator = sessions.entries.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                val session = entry.value
                val alive = session.onRetransmitTick(now)
                if (!alive || (checkIdle && now - session.lastActivityMs.get() > IDLE_TIMEOUT_MS)) {
                    iterator.remove()
                    session.close(sendReset = !alive)
                }
            }
            if (checkIdle) idleTickCounter = 0
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
            val session = TcpFlowSession(
                key = key,
                initialClientSeq = tcp.seqNum,
                clientMss = tcp.mss?.coerceIn(536, DEFAULT_MSS) ?: DEFAULT_MSS,
                clientWindowScaleShift = tcp.windowScaleShift,
                initialClientWindow = tcp.windowSize
            )
            sessions[key] = session
            session.onSynReceived()
            return
        }

        val session = sessions[key]
        if (session == null) {
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

        if (isAck) {
            session.onClientAck(tcp.ackNum, tcp.windowSize, hasPayload = tcp.payloadLength > 0)
        }

        if (tcp.payloadLength > 0) {
            val payload = rawPacket.copyOfRange(tcp.payloadOffset, tcp.payloadOffset + tcp.payloadLength)
            session.onClientData(tcp.seqNum, payload)
        }

        if (isFin) {
            session.onClientFin(tcp.seqNum, tcp.payloadLength)
        }
    }

    fun closeAll() {
        maintenanceJob.cancel()
        val all = sessions.values.toList()
        sessions.clear()
        for (session in all) {
            session.close(sendReset = false)
        }
    }

    private inner class TcpFlowSession(
        private val key: TcpFlowKey,
        initialClientSeq: Long,
        private val clientMss: Int,
        private val clientWindowScaleShift: Int?,
        initialClientWindow: Int
    ) {
        private val lock = Any()
        private var clientNextSeq: Long = (initialClientSeq + 1L) and 0xFFFFFFFFL
        private val initialServerSeq: Long = Random.nextInt(100_000, Int.MAX_VALUE).toLong() and 0xFFFFFFFFL
        private var serverNextSeq: Long = initialServerSeq
        private var serverUnackedSeq: Long = initialServerSeq
        private var clientWindowBytes: Int = (initialClientWindow shl (clientWindowScaleShift ?: 0)).coerceAtLeast(32_768)
        private var dupAckCount: Int = 0
        private var synAcked: Boolean = false

        // Worker -> TUN sliding window & retransmission buffers
        private val pendingSendQueue = ArrayDeque<ByteArray>()
        private var pendingHeadOffset = 0
        private val unackedSegments = ArrayDeque<SentSegment>()
        private var inFlightBytes = 0

        // TUN -> Worker out-of-order reassembly buffer
        private val oooClientSegments = TreeMap<Long, ByteArray> { a, b ->
            PacketUtils.seqDiff(a, b).compareTo(0L)
        }

        private var tunnelSession: WorkerTunnelSession? = null
        private var dialStarted = false
        private var clientFinReceived = false
        private var remoteClosed = false
        private var serverFinSent = false
        private var closed = false
        private var sniWaitJob: Job? = null
        val lastActivityMs = AtomicLong(System.currentTimeMillis())

        fun onSynReceived() {
            synchronized(lock) {
                val useScale = if (clientWindowScaleShift != null) PacketUtils.DEFAULT_WINDOW_SCALE else null
                val synAck = PacketUtils.buildIpv4TcpPacket(
                    srcIp = key.dstIp,
                    dstIp = key.srcIp,
                    srcPort = key.dstPort,
                    dstPort = key.srcPort,
                    seqNum = serverNextSeq,
                    ackNum = clientNextSeq,
                    flags = PacketUtils.TCP_SYN or PacketUtils.TCP_ACK,
                    windowSize = 65535,
                    includeSynOptions = true,
                    windowScaleShift = useScale,
                    mssValue = DEFAULT_MSS
                )
                val segStart = serverNextSeq
                serverNextSeq = (serverNextSeq + 1L) and 0xFFFFFFFFL
                unackedSegments.addLast(
                    SentSegment(
                        seqStart = segStart,
                        seqEnd = serverNextSeq,
                        payload = ByteArray(0),
                        flags = PacketUtils.TCP_SYN or PacketUtils.TCP_ACK,
                        sentAtMs = System.currentTimeMillis()
                    )
                )
                writePacketToTun(synAck)
            }

            val cachedDomain = lookupDomain(key.dstIp)
            val shouldSniff = sniSniffingEnabled &&
                cachedDomain == null &&
                (key.dstPort == 443 || key.dstPort == 80 || key.dstPort == 8443 || key.dstPort == 8080)

            if (!shouldSniff) {
                startWorkerDial(cachedDomain ?: PacketUtils.ipIntToString(key.dstIp), initialPayload = null)
            } else {
                sniWaitJob = scope.launch(Dispatchers.IO) {
                    delay(SNI_WAIT_TIMEOUT_MS)
                    startWorkerDial(PacketUtils.ipIntToString(key.dstIp), initialPayload = null)
                }
            }
        }

        fun onClientAck(ackNum: Long, rawWindowSize: Int, hasPayload: Boolean) {
            var shouldCleanup = false
            synchronized(lock) {
                if (closed) return
                val scale = clientWindowScaleShift ?: 0
                clientWindowBytes = (rawWindowSize shl scale).coerceAtLeast(0)

                val advance = PacketUtils.seqDiff(ackNum, serverUnackedSeq)
                val maxOutstanding = PacketUtils.seqDiff(serverNextSeq, serverUnackedSeq)

                if (advance > 0 && advance <= maxOutstanding) {
                    serverUnackedSeq = ackNum
                    dupAckCount = 0
                    synAcked = true

                    while (unackedSegments.isNotEmpty()) {
                        val head = unackedSegments.first()
                        if (PacketUtils.seqDiff(ackNum, head.seqEnd) >= 0) {
                            unackedSegments.removeFirst()
                            inFlightBytes = (inFlightBytes - head.payload.size).coerceAtLeast(0)
                        } else {
                            break
                        }
                    }

                    pumpSendQueueLocked()

                    if (serverFinSent && unackedSegments.isEmpty() && clientFinReceived) {
                        shouldCleanup = true
                    }
                } else if (advance == 0L && !hasPayload && unackedSegments.isNotEmpty()) {
                    // Track duplicate ACKs for Fast Retransmit (RFC 5681)
                    dupAckCount++
                    if (dupAckCount == 3) {
                        retransmitSegmentLocked(unackedSegments.first(), System.currentTimeMillis())
                    }
                } else if (clientWindowBytes > 0 && pendingSendQueue.isNotEmpty()) {
                    // Window update opened space
                    pumpSendQueueLocked()
                }
            }
            if (shouldCleanup) {
                sessions.remove(key)
                close(sendReset = false)
            }
        }

        fun onClientData(seqNum: Long, payload: ByteArray) {
            var contiguousToForward: ByteArray? = null
            synchronized(lock) {
                if (closed) return
                val diff = PacketUtils.seqDiff(seqNum, clientNextSeq)

                when {
                    diff == 0L -> {
                        // In-order fast path
                        clientNextSeq = (clientNextSeq + payload.size.toLong()) and 0xFFFFFFFFL
                        contiguousToForward = drainOutOfOrderLocked(payload)
                        sendAckOnlyLocked()
                    }
                    diff < 0L -> {
                        // Retransmission or partial overlap
                        val overlap = (-diff).toInt()
                        if (overlap < payload.size) {
                            val freshPart = payload.copyOfRange(overlap, payload.size)
                            clientNextSeq = (clientNextSeq + freshPart.size.toLong()) and 0xFFFFFFFFL
                            contiguousToForward = drainOutOfOrderLocked(freshPart)
                        }
                        sendAckOnlyLocked()
                    }
                    else -> {
                        // Out-of-order future segment: buffer up to MAX_OOO_SEGMENTS
                        if (oooClientSegments.size < MAX_OOO_SEGMENTS && diff < 262_144L) {
                            val existing = oooClientSegments[seqNum]
                            if (existing == null || payload.size > existing.size) {
                                oooClientSegments[seqNum] = payload
                            }
                        }
                        sendAckOnlyLocked()
                    }
                }
            }

            val data = contiguousToForward ?: return
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

        private fun drainOutOfOrderLocked(initialChunk: ByteArray): ByteArray {
            if (oooClientSegments.isEmpty()) return initialChunk
            val out = ByteArrayOutputStream(initialChunk.size * 2)
            out.write(initialChunk)

            val iter = oooClientSegments.entries.iterator()
            while (iter.hasNext()) {
                val entry = iter.next()
                val segSeq = entry.key
                val segData = entry.value
                val diff = PacketUtils.seqDiff(segSeq, clientNextSeq)
                if (diff > 0L) break
                iter.remove()
                val overlap = (-diff).toInt()
                if (overlap < segData.size) {
                    out.write(segData, overlap, segData.size - overlap)
                    clientNextSeq = (clientNextSeq + (segData.size - overlap).toLong()) and 0xFFFFFFFFL
                }
            }
            return out.toByteArray()
        }

        fun onClientFin(seqNum: Long, payloadLen: Int) {
            var shouldCloseNow = false
            synchronized(lock) {
                if (closed) return
                val finSeq = (seqNum + payloadLen.toLong()) and 0xFFFFFFFFL
                if (PacketUtils.seqDiff(finSeq, clientNextSeq) <= 0L) {
                    val afterFin = (finSeq + 1L) and 0xFFFFFFFFL
                    if (PacketUtils.seqDiff(afterFin, clientNextSeq) > 0L) {
                        clientNextSeq = afterFin
                    }
                    clientFinReceived = true
                    sendAckOnlyLocked()
                    if (remoteClosed && pendingSendQueue.isEmpty() && unackedSegments.isEmpty()) {
                        shouldCloseNow = true
                    } else if (!remoteClosed) {
                        // Client finished sending; if server already sent nothing pending, close cleanly
                        // after remote finishes or immediately if nothing is pending
                        shouldCloseNow = false
                    }
                }
            }
            if (shouldCloseNow) {
                sessions.remove(key)
                close(sendReset = false)
            }
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
                    enqueueRemoteData(remoteBytes)
                },
                onClosed = { errorReason ->
                    onRemoteTunnelClosed(hadError = errorReason != null)
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

        private fun enqueueRemoteData(data: ByteArray) {
            if (data.isEmpty()) return
            synchronized(lock) {
                if (closed) return
                pendingSendQueue.addLast(data)
                pumpSendQueueLocked()
            }
        }

        private fun onRemoteTunnelClosed(hadError: Boolean) {
            var shouldDropImmediately = false
            synchronized(lock) {
                if (closed) return
                remoteClosed = true
                if (hadError && pendingSendQueue.isEmpty() && unackedSegments.isEmpty()) {
                    shouldDropImmediately = true
                } else {
                    pumpSendQueueLocked()
                }
            }
            if (shouldDropImmediately) {
                sessions.remove(key)
                close(sendReset = true)
            }
        }

        private fun pumpSendQueueLocked() {
            if (closed || !synAcked) return
            val effectiveWindow = minOf(clientWindowBytes.coerceAtLeast(clientMss), MAX_IN_FLIGHT_BYTES)
            val now = System.currentTimeMillis()

            while (pendingSendQueue.isNotEmpty() && inFlightBytes < effectiveWindow) {
                val availableWindow = (effectiveWindow - inFlightBytes).coerceAtLeast(0)
                if (availableWindow <= 0) break

                val head = pendingSendQueue.first()
                val remainingInHead = head.size - pendingHeadOffset
                val chunkSize = minOf(remainingInHead, clientMss, availableWindow)
                if (chunkSize <= 0) break

                val segmentPayload = if (pendingHeadOffset == 0 && chunkSize == head.size) {
                    pendingSendQueue.removeFirst()
                    pendingHeadOffset = 0
                    head
                } else {
                    val slice = head.copyOfRange(pendingHeadOffset, pendingHeadOffset + chunkSize)
                    pendingHeadOffset += chunkSize
                    if (pendingHeadOffset >= head.size) {
                        pendingSendQueue.removeFirst()
                        pendingHeadOffset = 0
                    }
                    slice
                }

                val isQueueDrained = pendingSendQueue.isEmpty()
                val flags = PacketUtils.TCP_ACK or if (isQueueDrained) PacketUtils.TCP_PSH else 0
                val seqStart = serverNextSeq
                val seqEnd = (seqStart + segmentPayload.size.toLong()) and 0xFFFFFFFFL
                serverNextSeq = seqEnd
                inFlightBytes += segmentPayload.size

                val segment = SentSegment(
                    seqStart = seqStart,
                    seqEnd = seqEnd,
                    payload = segmentPayload,
                    flags = flags,
                    sentAtMs = now
                )
                unackedSegments.addLast(segment)

                val packet = PacketUtils.buildIpv4TcpPacket(
                    srcIp = key.dstIp,
                    dstIp = key.srcIp,
                    srcPort = key.dstPort,
                    dstPort = key.srcPort,
                    seqNum = seqStart,
                    ackNum = clientNextSeq,
                    flags = flags,
                    windowSize = 65535,
                    payload = segmentPayload
                )
                writePacketToTun(packet)
            }

            // If remote closed cleanly and all data has been pushed, send FIN|ACK
            if (remoteClosed && !serverFinSent && pendingSendQueue.isEmpty()) {
                serverFinSent = true
                val seqStart = serverNextSeq
                val seqEnd = (seqStart + 1L) and 0xFFFFFFFFL
                serverNextSeq = seqEnd
                val flags = PacketUtils.TCP_FIN or PacketUtils.TCP_ACK
                unackedSegments.addLast(
                    SentSegment(
                        seqStart = seqStart,
                        seqEnd = seqEnd,
                        payload = ByteArray(0),
                        flags = flags,
                        sentAtMs = now
                    )
                )
                val finPacket = PacketUtils.buildIpv4TcpPacket(
                    srcIp = key.dstIp,
                    dstIp = key.srcIp,
                    srcPort = key.dstPort,
                    dstPort = key.srcPort,
                    seqNum = seqStart,
                    ackNum = clientNextSeq,
                    flags = flags,
                    windowSize = 65535
                )
                writePacketToTun(finPacket)
            }
        }

        fun onRetransmitTick(now: Long): Boolean {
            synchronized(lock) {
                if (closed) return false
                if (clientFinReceived && !remoteClosed && pendingSendQueue.isEmpty() &&
                    unackedSegments.isEmpty() && now - lastActivityMs.get() > 3_000L
                ) {
                    return false
                }
                if (unackedSegments.isEmpty()) {
                    // Clean up completed half-closed flows
                    if (serverFinSent && (clientFinReceived || now - lastActivityMs.get() > 10_000L)) {
                        return false
                    }
                    return true
                }
                val head = unackedSegments.first()
                val rto = (BASE_RTO_MS shl head.retries.coerceAtMost(3)).coerceAtMost(MAX_RTO_MS)
                if (now - head.sentAtMs >= rto) {
                    if (head.retries >= MAX_RETRIES) {
                        return false
                    }
                    retransmitSegmentLocked(head, now)
                }
                return true
            }
        }

        private fun retransmitSegmentLocked(segment: SentSegment, now: Long) {
            segment.sentAtMs = now
            segment.retries++
            val isSynAck = (segment.flags and PacketUtils.TCP_SYN) != 0
            val useScale = if (isSynAck && clientWindowScaleShift != null) {
                PacketUtils.DEFAULT_WINDOW_SCALE
            } else null

            val packet = PacketUtils.buildIpv4TcpPacket(
                srcIp = key.dstIp,
                dstIp = key.srcIp,
                srcPort = key.dstPort,
                dstPort = key.srcPort,
                seqNum = segment.seqStart,
                ackNum = clientNextSeq,
                flags = segment.flags,
                windowSize = 65535,
                payload = segment.payload,
                includeSynOptions = isSynAck,
                windowScaleShift = useScale,
                mssValue = DEFAULT_MSS
            )
            writePacketToTun(packet)
        }

        private fun sendAckOnlyLocked() {
            val ackPacket = PacketUtils.buildIpv4TcpPacket(
                srcIp = key.dstIp,
                dstIp = key.srcIp,
                srcPort = key.dstPort,
                dstPort = key.srcPort,
                seqNum = serverNextSeq,
                ackNum = clientNextSeq,
                flags = PacketUtils.TCP_ACK,
                windowSize = 65535
            )
            writePacketToTun(ackPacket)
        }

        fun close(sendReset: Boolean) {
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
                pendingSendQueue.clear()
                unackedSegments.clear()
                oooClientSegments.clear()
                inFlightBytes = 0

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
                }
            }
            if (wasDialed) {
                activeTunnelCounter.decrementAndGet()
            }
            wsToClose?.close()
        }
    }
}
