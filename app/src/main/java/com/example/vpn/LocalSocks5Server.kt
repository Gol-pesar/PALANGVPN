package com.example.vpn

import com.example.vpn.protocol.WorkerTunnelSession
import com.example.vpn.protocol.WorkerWebSocketClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Production-grade loopback RFC 1928 SOCKS5 server feeding native C lwIP (hev-socks5-tunnel)
 * and external local proxy clients:
 * - Supports SOCKS5 pipelining (`pipeline: true` in hev-socks5-tunnel)
 * - Zero-wait CONNECT reply so the app immediately streams TLS ClientHello / HTTP GET
 * - Coalesces split TLS ClientHello (e.g. Chrome ML-KEM 1.7KB) into ONE 0-RTT WebSocket frame
 * - Domain lookup + TLS SNI / HTTP Host sniffing when Fake DNS is disabled
 * - Natural TCP backpressure via loopback socket + 256KB buffers + dedicated cached thread pool
 * - RFC 1928 UDP ASSOCIATE (CMD=0x03) for Local DoH / Remote TCP DNS when Fake DNS is OFF,
 *   and instant QUIC UDP rejection when Fake DNS (native C mapdns) is ON
 */
class LocalSocks5Server(
    private val requestedPort: Int,
    private val scope: CoroutineScope,
    private val wsClient: WorkerWebSocketClient,
    private val dnsHandler: DnsProxyHandler,
    private val fakeDnsEnabled: Boolean,
    private val sniSniffingEnabled: Boolean,
    private val onBytesSent: (Int) -> Unit,
    private val onBytesReceived: (Int) -> Unit
) {
    private var serverSocket: ServerSocket? = null
    private var executor: ExecutorService? = null
    private val running = AtomicBoolean(false)
    private val activeConnections = AtomicInteger(0)

    @Volatile
    var boundPort: Int = requestedPort
        private set

    val activeSessionCount: Int
        get() = activeConnections.get().coerceAtLeast(0)

    fun start(): Boolean {
        if (!running.compareAndSet(false, true)) return true
        return try {
            val ss = ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), requestedPort), 256)
            }
            serverSocket = ss
            boundPort = ss.localPort
            val pool = Executors.newCachedThreadPool { runnable ->
                Thread(runnable, "edgetunnel-socks").apply { isDaemon = true }
            }
            executor = pool

            pool.execute {
                while (running.get() && !ss.isClosed) {
                    val client = try {
                        ss.accept()
                    } catch (_: Exception) {
                        break
                    }
                    pool.execute { handleClient(client) }
                }
            }
            true
        } catch (e: Exception) {
            running.set(false)
            VpnStateHolder.log(LogLevel.WARN, "پروکسی محلی SOCKS5 روی پورت $requestedPort باز نشد: ${e.message}")
            false
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null
        try {
            executor?.shutdownNow()
        } catch (_: Exception) {
        }
        executor = null
    }

    private fun handleClient(socket: Socket) {
        var counted = false
        var wsSession: WorkerTunnelSession? = null
        try {
            socket.tcpNoDelay = true
            runCatching {
                socket.receiveBufferSize = 262_144
                socket.sendBufferSize = 262_144
            }

            val bufferedIn = BufferedInputStream(socket.getInputStream(), 65_536)
            val input = DataInputStream(bufferedIn)
            val output = socket.getOutputStream()

            // 1) SOCKS5 Greeting: VER(1), NMETHODS(1), METHODS(N)
            val ver = input.readUnsignedByte()
            if (ver != 0x05) {
                socket.close()
                return
            }
            val nMethods = input.readUnsignedByte()
            if (nMethods > 0) {
                val methods = ByteArray(nMethods)
                input.readFully(methods)
            }
            // Reply: VER=5, METHOD=0 (NO AUTH)
            output.write(byteArrayOf(0x05, 0x00))
            // Only flush immediately if client did NOT pipeline the CONNECT request behind the greeting
            if (bufferedIn.available() == 0) {
                output.flush()
            }

            // 2) SOCKS5 Request: VER(1), CMD(1), RSV(1), ATYP(1), DST.ADDR, DST.PORT(2)
            val reqVer = input.readUnsignedByte()
            val cmd = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val atyp = input.readUnsignedByte()

            var rawIpv4Int: Int? = null
            val rawHost = when (atyp) {
                0x01 -> {
                    val addr = ByteArray(4)
                    input.readFully(addr)
                    rawIpv4Int = PacketUtils.ipv4BytesToInt(addr, 0)
                    PacketUtils.ipIntToString(rawIpv4Int)
                }
                0x03 -> {
                    val len = input.readUnsignedByte()
                    val domain = ByteArray(len)
                    input.readFully(domain)
                    String(domain, Charsets.UTF_8)
                }
                0x04 -> {
                    val addr = ByteArray(16)
                    input.readFully(addr)
                    InetAddress.getByAddress(addr).hostAddress ?: ""
                }
                else -> {
                    socket.close()
                    return
                }
            }
            val dstPort = input.readUnsignedShort()

            if (reqVer != 0x05) {
                socket.close()
                return
            }

            when (cmd) {
                0x01 -> { // TCP CONNECT
                    if (rawHost.isBlank() || dstPort !in 1..65535) {
                        output.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        socket.close()
                        return
                    }

                    // Zero-wait SOCKS5 CONNECT success reply so client immediately sends TLS ClientHello / HTTP request!
                    output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    output.flush()

                    activeConnections.incrementAndGet()
                    counted = true

                    val cachedDomain = if (atyp == 0x01 && rawIpv4Int != null) {
                        dnsHandler.lookupDomainForIp(rawIpv4Int)
                    } else null

                    val knownDomain = when {
                        atyp == 0x03 -> rawHost
                        cachedDomain != null -> cachedDomain
                        else -> null
                    }

                    val shouldSniffFirst = knownDomain == null &&
                        sniSniffingEnabled &&
                        (dstPort == 443 || dstPort == 80 || dstPort == 8443 || dstPort == 8080)

                    val tunnelClosed = AtomicBoolean(false)
                    val writeLock = Any()

                    fun openWorker(hostToDial: String): WorkerTunnelSession {
                        return wsClient.openTunnel(
                            targetHost = hostToDial,
                            targetPort = dstPort,
                            onData = { data ->
                                try {
                                    synchronized(writeLock) {
                                        if (!tunnelClosed.get()) {
                                            output.write(data)
                                        }
                                    }
                                } catch (_: Exception) {
                                    tunnelClosed.set(true)
                                    try { socket.close() } catch (_: Exception) {}
                                }
                            },
                            onClosed = {
                                tunnelClosed.set(true)
                                try { socket.close() } catch (_: Exception) {}
                            },
                            onBytesSent = onBytesSent,
                            onBytesReceived = onBytesReceived
                        )
                    }

                    val buffer = ByteArray(65_536)
                    val session: WorkerTunnelSession

                    if (!shouldSniffFirst) {
                        // We already know the real domain (Fake DNS mapdns or DNS cache) -> dial Worker IMMEDIATELY!
                        session = openWorker(knownDomain ?: rawHost)
                        wsSession = session

                        // Coalesce split TLS ClientHello (e.g. Chrome ML-KEM) into ONE clean 0-RTT frame
                        val firstChunk = readFirstFlightCoalesced(socket, bufferedIn, buffer, initialTimeoutMs = 0)
                        if (firstChunk == null) {
                            session.close()
                            return
                        }
                        if (firstChunk.isNotEmpty() && !session.send(firstChunk)) {
                            session.close()
                            return
                        }
                    } else {
                        // Raw IP without Fake DNS: briefly wait up to 50ms for ClientHello/HTTP to sniff real SNI
                        val firstChunk = readFirstFlightCoalesced(socket, bufferedIn, buffer, initialTimeoutMs = 50)
                        val targetHost = if (firstChunk != null && firstChunk.isNotEmpty()) {
                            PacketUtils.extractTlsSni(firstChunk)
                                ?: PacketUtils.extractHttpHost(firstChunk)
                                ?: rawHost
                        } else {
                            rawHost
                        }
                        session = openWorker(targetHost)
                        wsSession = session
                        if (firstChunk == null) {
                            session.close()
                            return
                        }
                        if (firstChunk.isNotEmpty() && !session.send(firstChunk)) {
                            session.close()
                            return
                        }
                    }

                    // High-throughput steady-state upload loop (64KB chunks)
                    while (!tunnelClosed.get() && running.get()) {
                        val read = bufferedIn.read(buffer)
                        if (read <= 0) break
                        val chunk = buffer.copyOf(read)
                        if (!session.send(chunk)) break
                    }
                    session.close()
                }

                0x03 -> { // RFC 1928 UDP ASSOCIATE
                    if (fakeDnsEnabled) {
                        // Native C mapdns already handles 100% of DNS in <0.05ms!
                        // Reject non-DNS UDP (QUIC UDP/443) immediately so Chrome uses fast TCP/443.
                        output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                        socket.close()
                        return
                    }
                    handleUdpAssociate(socket, bufferedIn, output)
                }

                else -> {
                    output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    output.flush()
                    socket.close()
                }
            }
        } catch (_: Exception) {
        } finally {
            wsSession?.close()
            if (counted) {
                activeConnections.decrementAndGet()
            }
            try { socket.close() } catch (_: Exception) {}
        }
    }

    /**
     * Reads the initial client payload and, if it begins with a TLS Handshake record (0x16 0x03)
     * whose record length exceeds the first read (such as Chrome's ~1.7KB ML-KEM ClientHello),
     * coalesces the remainder within 15ms into a single byte array for clean single-frame 0-RTT.
     *
     * Returns null on immediate EOF, empty ByteArray on initial read timeout (server-speaks-first),
     * or the coalesced payload bytes.
     */
    private fun readFirstFlightCoalesced(
        socket: Socket,
        input: BufferedInputStream,
        buffer: ByteArray,
        initialTimeoutMs: Int
    ): ByteArray? {
        if (initialTimeoutMs > 0) {
            runCatching { socket.soTimeout = initialTimeoutMs }
        }
        val firstRead = try {
            input.read(buffer)
        } catch (_: SocketTimeoutException) {
            runCatching { socket.soTimeout = 0 }
            return ByteArray(0)
        }
        if (initialTimeoutMs > 0) {
            runCatching { socket.soTimeout = 0 }
        }
        if (firstRead <= 0) return null

        // Check if this is an incomplete TLS Handshake record (0x16 0x03 xx lenHi lenLo)
        if (firstRead >= 5 &&
            (buffer[0].toInt() and 0xFF) == 0x16 &&
            (buffer[1].toInt() and 0xFF) == 0x03
        ) {
            val expectedTotal = 5 + PacketUtils.readUInt16(buffer, 3)
            if (expectedTotal in (firstRead + 1)..16_389) {
                val out = ByteArrayOutputStream(expectedTotal)
                out.write(buffer, 0, firstRead)
                runCatching { socket.soTimeout = 15 }
                try {
                    while (out.size() < expectedTotal) {
                        val remain = (expectedTotal - out.size()).coerceAtMost(buffer.size)
                        val n = input.read(buffer, 0, remain)
                        if (n <= 0) break
                        out.write(buffer, 0, n)
                    }
                } catch (_: SocketTimeoutException) {
                    // Send whatever we have so far
                } finally {
                    runCatching { socket.soTimeout = 0 }
                }
                return out.toByteArray()
            }
        }

        return buffer.copyOf(firstRead)
    }

    /**
     * Standard RFC 1928 UDP ASSOCIATE handler used when Fake DNS is disabled:
     * relays UDP/53 DNS queries through our Local DoH / Remote Worker TCP DNS engine
     * and drops non-DNS UDP (like QUIC UDP/443).
     */
    private fun handleUdpAssociate(
        controlSocket: Socket,
        controlIn: BufferedInputStream,
        controlOut: java.io.OutputStream
    ) {
        val udpSocket = try {
            DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        } catch (_: Exception) {
            controlOut.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            controlOut.flush()
            return
        }
        val udpPort = udpSocket.localPort
        val assocOpen = AtomicBoolean(true)

        try {
            controlOut.write(
                byteArrayOf(
                    0x05, 0x00, 0x00, 0x01,
                    127, 0, 0, 1,
                    ((udpPort ushr 8) and 0xFF).toByte(),
                    (udpPort and 0xFF).toByte()
                )
            )
            controlOut.flush()

            // Monitor TCP control connection in background; closing it ends the UDP association
            executor?.execute {
                val sink = ByteArray(16)
                try {
                    while (assocOpen.get() && running.get()) {
                        if (controlIn.read(sink) < 0) break
                    }
                } catch (_: Exception) {
                } finally {
                    assocOpen.set(false)
                    try { udpSocket.close() } catch (_: Exception) {}
                }
            }

            val recvBuf = ByteArray(4096)
            val sendLock = Any()
            while (assocOpen.get() && running.get() && !udpSocket.isClosed) {
                val packet = DatagramPacket(recvBuf, recvBuf.size)
                try {
                    udpSocket.receive(packet)
                } catch (_: Exception) {
                    break
                }
                val len = packet.length
                if (len < 10) continue
                val data = recvBuf.copyOf(len)
                val frag = data[2].toInt() and 0xFF
                if (frag != 0) continue

                val atyp = data[3].toInt() and 0xFF
                val headerEnd = when (atyp) {
                    0x01 -> 4 + 4 + 2
                    0x03 -> {
                        val dLen = data[4].toInt() and 0xFF
                        4 + 1 + dLen + 2
                    }
                    0x04 -> 4 + 16 + 2
                    else -> continue
                }
                if (headerEnd > len) continue
                val dstPort = PacketUtils.readUInt16(data, headerEnd - 2)
                if (dstPort != 53) continue // Only relay DNS over UDP; drop QUIC/non-DNS UDP

                val headerCopy = data.copyOfRange(0, headerEnd)
                val dnsPayload = data.copyOfRange(headerEnd, len)
                val replyAddr = packet.address
                val replyPort = packet.port

                scope.launch(Dispatchers.IO) {
                    val dnsReply = dnsHandler.resolveRawDnsQuery(dnsPayload) ?: return@launch
                    if (!assocOpen.get() || udpSocket.isClosed) return@launch
                    val outBytes = ByteArray(headerCopy.size + dnsReply.size)
                    System.arraycopy(headerCopy, 0, outBytes, 0, headerCopy.size)
                    System.arraycopy(dnsReply, 0, outBytes, headerCopy.size, dnsReply.size)
                    val outPacket = DatagramPacket(outBytes, outBytes.size, replyAddr, replyPort)
                    synchronized(sendLock) {
                        runCatching { udpSocket.send(outPacket) }
                    }
                }
            }
        } finally {
            assocOpen.set(false)
            try { udpSocket.close() } catch (_: Exception) {}
        }
    }
}
