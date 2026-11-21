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
 * High-throughput, stall-free user-space TCP engine with:
 * - RFC 7323 Window Scaling & MSS (1360)
 * - TCP Slow-Start + Congestion Window (cwnd) + NewReno Fast Recovery (prevents TUN overflow stalls!)
 * - 180ms fast RTO timer + 3-dup-ACK Fast Retransmit
 * - Fake DNS instant domain resolution + 0-RTT pre-warmed Worker WebSocket dialing on SYN
 * - Out-of-order client segment reassembly
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
        private const val INITIAL_CWND_SEGMENTS = 16
        private const val INITIAL_SSTHRESH = 131_072   // 128 KB
        private const val MAX_CWND_BYTES = 524_288     // 512 KB
        private const val IDLE_TIMEOUT_MS = 90_000L
        private const val SNI_WAIT_TIMEOUT_MS = 65L
        private const val RETRANSMIT_TICK_MS = 80L
        private const val BASE_RTO_MS = 180L
        private const val MAX_RTO_MS = 1_600L
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
            val checkIdle = idleTickCounter >= 180 // ~14.4 seconds

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

        // NewReno congestion control (prevents TUN burst overflow & recovers multiple losses in 1 RTT)
        private var cwndBytes: Int = INITIAL_CWND_SEGMENTS * clientMss
        private var ssthreshBytes: Int = INITIAL_SSTHRESH
        private var inRecovery: Boolean = false
        private var recoverSeq: Long = initialServerSeq
        private var dupAckCount: Int = 0
        private var synAcked: Boolean = false

        private val pendingSendQueue = ArrayDeque<ByteArray>()
        private var pendingHeadOffset = 0
        private val unackedSegments = ArrayDeque<SentSegment>()
        private var inFlightBytes = 0

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

            // Look up Fake DNS or real DNS cache first — if found, dial Worker IMMEDIATELY on SYN!
            val cachedDomain = lookupDomain(key.dstIp)
            val isUnmappedFakeIp = cachedDomain == null && FakeDnsPool.isFakeIp(key.dstIp)
            val shouldSniff = (sniSniffingEnabled || isUnmappedFakeIp) &&
                cachedDomain == null &&
                (key.dstPort == 443 || key.dstPort == 80 || key.dstPort == 8443 || key.dstPort == 8080)

            if (!shouldSniff) {
                if (isUnmappedFakeIp) {
                    // Fake IP expired from pool and no SNI port; reset cleanly so app re-queries DNS
                    sessions.remove(key)
                    close(sendReset = true)
                    return
                }
                startWorkerDial(cachedDomain ?: PacketUtils.ipIntToString(key.dstIp), initialPayload = null)
            } else {
                sniWaitJob = scope.launch(Dispatchers.IO) {
                    delay(SNI_WAIT_TIMEOUT_MS)
                    if (!isUnmappedFakeIp) {
                        startWorkerDial(PacketUtils.ipIntToString(key.dstIp), initialPayload = null)
                    }
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

                    var newlyAckedBytes = 0
                    while (unackedSegments.isNotEmpty()) {
                        val head = unackedSegments.first()
                        if (PacketUtils.seqDiff(ackNum, head.seqEnd) >= 0) {
                            unackedSegments.removeFirst()
                            inFlightBytes = (inFlightBytes - head.payload.size).coerceAtLeast(0)
                            newlyAckedBytes += head.payload.size
                        } else {
                            break
                        }
                    }

                    // NewReno partial-ACK handling: if still in recovery and more lost segments remain,
                    // immediately retransmit the next missing head instead of waiting for RTO!
                    if (inRecovery) {
                        if (PacketUtils.seqDiff(ackNum, recoverSeq) >= 0) {
                            inRecovery = false
                            cwndBytes = ssthreshBytes.coerceAtLeast(8 * clientMss)
                        } else if (unackedSegments.isNotEmpty()) {
                            retransmitSegmentLocked(unackedSegments.first(), System.currentTimeMillis())
                        }
                    } else if (newlyAckedBytes > 0) {
                        // Slow Start -> Congestion Avoidance
                        cwndBytes = if (cwndBytes < ssthreshBytes) {
                            (cwndBytes + newlyAckedBytes).coerceAtMost(MAX_CWND_BYTES)
                        } else {
                            val increment = ((clientMss.toLong() * newlyAckedBytes) / cwndBytes.coerceAtLeast(clientMss))
                                .toInt().coerceAtLeast(1)
                            (cwndBytes + increment).coerceAtMost(MAX_CWND_BYTES)
                        }
                    }

                    pumpSendQueueLocked()

                    if (serverFinSent && unackedSegments.isEmpty() && clientFinReceived) {
                        shouldCleanup = true
                    }
                } else if (advance == 0L && !hasPayload && unackedSegments.isNotEmpty()) {
                    dupAckCount++
                    if (dupAckCount == 3) {
                        ssthreshBytes = (cwndBytes / 2).coerceAtLeast(8 * clientMss)
                        cwndBytes = ssthreshBytes + 3 * clientMss
                        inRecovery = true
                        recoverSeq = serverNextSeq
                        retransmitSegmentLocked(unackedSegments.first(), System.currentTimeMillis())
                    } else if (dupAckCount > 3 && inRecovery) {
                        cwndBytes = (cwndBytes + clientMss).coerceAtMost(MAX_CWND_BYTES)
                        pumpSendQueueLocked()
                    }
                } else if (clientWindowBytes > 0 && pendingSendQueue.isNotEmpty()) {
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
                        clientNextSeq = (clientNextSeq + payload.size.toLong()) and 0xFFFFFFFFL
                        contiguousToForward = drainOutOfOrderLocked(payload)
                        sendAckOnlyLocked()
                    }
                    diff < 0L -> {
                        val overlap = (-diff).toInt()
                        if (overlap < payload.size) {
                            val freshPart = payload.copyOfRange(overlap, payload.size)
                            clientNextSeq = (clientNextSeq + freshPart.size.toLong()) and 0xFFFFFFFFL
                            contiguousToForward = drainOutOfOrderLocked(freshPart)
                        }
                        sendAckOnlyLocked()
                    }
                    else -> {
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
                val sniffedHost = if (sniSniffingEnabled || FakeDnsPool.isFakeIp(key.dstIp)) {
                    PacketUtils.extractTlsSni(data) ?: PacketUtils.extractHttpHost(data)
                } else null
                val targetHost = sniffedHost ?: lookupDomain(key.dstIp) ?: run {
                    if (FakeDnsPool.isFakeIp(key.dstIp)) {
                        sessions.remove(key)
                        close(sendReset = true)
                        return
                    }
                    PacketUtils.ipIntToString(key.dstIp)
                }
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
            val effectiveWindow = minOf(clientWindowBytes.coerceAtLeast(clientMss), cwndBytes)
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
                    // RTO backoff on cwnd
                    ssthreshBytes = (cwndBytes / 2).coerceAtLeast(8 * clientMss)
                    cwndBytes = 8 * clientMss
                    inRecovery = false
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
