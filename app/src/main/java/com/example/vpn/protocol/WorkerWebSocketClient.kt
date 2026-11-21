package com.example.vpn.protocol

import com.example.vpn.LogLevel
import com.example.vpn.VpnStateHolder
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import okhttp3.Dispatcher
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.net.InetAddress
import java.net.Socket
import java.net.UnknownHostException
import java.util.ArrayDeque
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory

sealed interface HandshakeTestResult {
    data class Success(val latencyMs: Int, val resolvedIp: String) : HandshakeTestResult
    data class Failure(val reason: String) : HandshakeTestResult
}

/**
 * Ultra-low-latency OkHttp WebSocket & Local DoH engine for worker_534a9c26.js:
 * - Pre-Warmed WebSocket Pool (4 idle TLS+WS connections ready for 0ms checkout)
 * - 0-RTT Data Pipelining (sends XOR-encrypted initial client payload right after Init,
 *   utilizing the worker's st.q queue while still strictly verifying HMAC-SHA256 "OK" ACK)
 * - 256 concurrent per-host connections + TCP_NODELAY + 128KB socket buffers
 * - Built-in HTTP/2 DoH client routed through the user's Clean IP for Local DNS on port 443
 */
class WorkerWebSocketClient(
    private val config: WorkerConfig
) {
    companion object {
        private const val WARM_POOL_TARGET = 4
        private const val WARM_MAX_AGE_MS = 24_000L
        private val DNS_MESSAGE_MEDIA_TYPE = "application/dns-message".toMediaType()

        suspend fun testHandshake(config: WorkerConfig): HandshakeTestResult {
            val validationError = config.validate()
            if (validationError != null) {
                return HandshakeTestResult.Failure(validationError)
            }

            val endpoint = config.parseEndpoint()
                ?: return HandshakeTestResult.Failure("Worker URL نامعتبر است")

            val client = WorkerWebSocketClient(config)
            val resultDeferred = CompletableDeferred<HandshakeTestResult>()
            val totalStartNanos = System.nanoTime()
            var wsOpenedNanos = totalStartNanos

            VpnStateHolder.log(
                LogLevel.INFO,
                "تست هندشیک: ${endpoint.workerHost}:${endpoint.port}" +
                    (endpoint.cleanIpHost?.let { " via Clean IP $it" } ?: " (Direct DNS)")
            )

            var session: WorkerTunnelSession? = null
            return try {
                session = client.openTunnel(
                    targetHost = "www.gstatic.com",
                    targetPort = 80,
                    onWsOpened = {
                        wsOpenedNanos = System.nanoTime()
                    },
                    onReady = {
                        val nowNanos = System.nanoTime()
                        val tunnelRttMs = ((nowNanos - wsOpenedNanos) / 1_000_000L).toInt().coerceAtLeast(1)
                        val totalColdMs = ((nowNanos - totalStartNanos) / 1_000_000L).toInt().coerceAtLeast(1)
                        val resolved = client.lastResolvedIp
                        VpnStateHolder.log(
                            LogLevel.SUCCESS,
                            "هندشیک موفق (HMAC-SHA256 OK) — پینگ تونل: ${tunnelRttMs}ms | اتصال کل: ${totalColdMs}ms [$resolved]"
                        )
                        resultDeferred.complete(HandshakeTestResult.Success(tunnelRttMs, resolved))
                    },
                    onData = {},
                    onClosed = { reason ->
                        if (!resultDeferred.isCompleted) {
                            val msg = reason ?: "اتصال پیش از دریافت ACK بسته شد"
                            VpnStateHolder.log(LogLevel.ERROR, "تست ناموفق: $msg")
                            resultDeferred.complete(HandshakeTestResult.Failure(msg))
                        }
                    }
                )
                withTimeout(8_000L) {
                    resultDeferred.await()
                }
            } catch (e: Exception) {
                val msg = e.message ?: "زمان اتصال به پایان رسید (Timeout)"
                VpnStateHolder.log(LogLevel.ERROR, "خطای تست اتصال: $msg")
                HandshakeTestResult.Failure(msg)
            } finally {
                session?.close()
                client.shutdown()
            }
        }
    }

    private val endpoint: ParsedWorkerEndpoint =
        config.parseEndpoint() ?: throw IllegalArgumentException("Invalid Worker URL")

    @Volatile
    var lastResolvedIp: String = endpoint.cleanIpHost ?: endpoint.workerHost
        private set

    @Volatile
    private var cachedAddresses: List<InetAddress>? = null

    @Volatile
    private var cachedAtMs: Long = 0L

    private val isShutdown = AtomicBoolean(false)

    private val customDns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val now = System.currentTimeMillis()
            val cached = cachedAddresses
            if (cached != null && now - cachedAtMs < 120_000L) {
                return cached
            }

            val cleanHost = endpoint.cleanIpHost
            val resolved = if (!cleanHost.isNullOrBlank()) {
                val addresses = InetAddress.getAllByName(cleanHost).toList()
                if (addresses.isEmpty()) throw UnknownHostException("Clean IP unresolved: $cleanHost")
                addresses
            } else {
                Dns.SYSTEM.lookup(hostname)
            }
            resolved.firstOrNull()?.hostAddress?.let { lastResolvedIp = it }
            cachedAddresses = resolved
            cachedAtMs = now
            return resolved
        }
    }

    private val lowLatencySocketFactory = object : SocketFactory() {
        private val delegate = getDefault()

        private fun tune(socket: Socket): Socket = socket.apply {
            runCatching {
                tcpNoDelay = true
                sendBufferSize = 131_072
                receiveBufferSize = 131_072
            }
        }

        override fun createSocket(): Socket = tune(delegate.createSocket())
        override fun createSocket(host: String?, port: Int): Socket = tune(delegate.createSocket(host, port))
        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
            tune(delegate.createSocket(host, port, localHost, localPort))
        override fun createSocket(host: InetAddress?, port: Int): Socket = tune(delegate.createSocket(host, port))
        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            tune(delegate.createSocket(address, port, localAddress, localPort))
    }

    private val highConcurrencyDispatcher = Dispatcher(
        ThreadPoolExecutor(
            8,
            256,
            60L,
            TimeUnit.SECONDS,
            SynchronousQueue()
        )
    ).apply {
        maxRequests = 256
        maxRequestsPerHost = 256
    }

    private val okHttpClient: OkHttpClient = OkHttpClient.Builder()
        .dispatcher(highConcurrencyDispatcher)
        .dns(customDns)
        .socketFactory(lowLatencySocketFactory)
        .protocols(listOf(Protocol.HTTP_1_1))
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .pingInterval(25, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .build()

    // Dedicated HTTP/2 client for Local DNS over HTTPS (DoH) via Clean IP (port 443)
    private val dohCleanIpClient: OkHttpClient = OkHttpClient.Builder()
        .dns(customDns)
        .socketFactory(lowLatencySocketFactory)
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(4, TimeUnit.SECONDS)
        .writeTimeout(4, TimeUnit.SECONDS)
        .build()

    // Fallback direct HTTP/2 DoH client (system DNS, bypassed from VPN via self-bypass)
    private val dohDirectClient: OkHttpClient = OkHttpClient.Builder()
        .socketFactory(lowLatencySocketFactory)
        .connectTimeout(4, TimeUnit.SECONDS)
        .readTimeout(4, TimeUnit.SECONDS)
        .writeTimeout(4, TimeUnit.SECONDS)
        .build()

    // Pre-warmed idle WebSocket pool
    private class WarmSlot(
        val webSocket: WebSocket,
        val delegate: SwitchableWebSocketListener,
        val openedAtMs: Long
    )

    private class SwitchableWebSocketListener(
        private val onWarmOpen: (WebSocket, SwitchableWebSocketListener) -> Unit,
        private val onWarmDead: (SwitchableWebSocketListener) -> Unit
    ) : WebSocketListener() {
        @Volatile
        private var target: WebSocketListener? = null

        @Volatile
        var dead: Boolean = false
            private set

        fun attachTarget(listener: WebSocketListener): Boolean {
            if (dead) return false
            target = listener
            return true
        }

        fun clearTarget() {
            target = null
        }

        override fun onOpen(webSocket: WebSocket, response: Response) {
            val t = target
            if (t != null) {
                t.onOpen(webSocket, response)
            } else {
                onWarmOpen(webSocket, this)
            }
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            target?.onMessage(webSocket, bytes)
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            target?.onMessage(webSocket, text)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            dead = true
            val t = target
            if (t != null) t.onClosing(webSocket, code, reason) else {
                webSocket.close(1000, null)
                onWarmDead(this)
            }
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            dead = true
            val t = target
            if (t != null) t.onClosed(webSocket, code, reason) else onWarmDead(this)
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            dead = true
            val listener = target
            if (listener != null) listener.onFailure(webSocket, t, response) else onWarmDead(this)
        }
    }

    private val poolLock = Any()
    private val warmPool = ArrayDeque<WarmSlot>()
    private val inFlightWarmups = AtomicInteger(0)
    private var warmPoolJob: Job? = null
    private var warmPoolScope: CoroutineScope? = null

    fun startWarmPool(scope: CoroutineScope) {
        warmPoolScope = scope
        refillWarmPool()
        warmPoolJob?.cancel()
        warmPoolJob = scope.launch(Dispatchers.IO) {
            while (isActive && !isShutdown.get()) {
                delay(6_000L)
                pruneExpiredWarmSlots()
                refillWarmPool()
            }
        }
    }

    private fun pruneExpiredWarmSlots() {
        val now = System.currentTimeMillis()
        val toClose = mutableListOf<WebSocket>()
        synchronized(poolLock) {
            val iter = warmPool.iterator()
            while (iter.hasNext()) {
                val slot = iter.next()
                if (slot.delegate.dead || now - slot.openedAtMs > WARM_MAX_AGE_MS) {
                    iter.remove()
                    toClose.add(slot.webSocket)
                }
            }
        }
        for (ws in toClose) {
            runCatching { ws.close(1000, "expired") }
        }
    }

    private fun refillWarmPool() {
        if (isShutdown.get()) return
        val needed = synchronized(poolLock) {
            (WARM_POOL_TARGET - warmPool.size - inFlightWarmups.get()).coerceAtLeast(0)
        }
        repeat(needed) {
            if (isShutdown.get()) return
            inFlightWarmups.incrementAndGet()
            val settled = AtomicBoolean(false)
            val switchable = SwitchableWebSocketListener(
                onWarmOpen = { ws, listener ->
                    if (settled.compareAndSet(false, true)) {
                        inFlightWarmups.updateAndGet { (it - 1).coerceAtLeast(0) }
                    }
                    if (isShutdown.get()) {
                        runCatching { ws.close(1000, "shutdown") }
                    } else {
                        val added = synchronized(poolLock) {
                            if (warmPool.size < WARM_POOL_TARGET + 2) {
                                warmPool.addLast(WarmSlot(ws, listener, System.currentTimeMillis()))
                                true
                            } else false
                        }
                        if (!added) runCatching { ws.close(1000, "overflow") }
                    }
                },
                onWarmDead = { deadListener ->
                    if (settled.compareAndSet(false, true)) {
                        inFlightWarmups.updateAndGet { (it - 1).coerceAtLeast(0) }
                    }
                    synchronized(poolLock) {
                        val iter = warmPool.iterator()
                        while (iter.hasNext()) {
                            if (iter.next().delegate === deadListener) {
                                iter.remove()
                                break
                            }
                        }
                    }
                }
            )
            okHttpClient.newWebSocket(buildWsRequest(), switchable)
        }
    }

    private fun checkoutWarmSlot(): WarmSlot? {
        val now = System.currentTimeMillis()
        val expired = mutableListOf<WebSocket>()
        var picked: WarmSlot? = null
        synchronized(poolLock) {
            while (warmPool.isNotEmpty()) {
                val candidate = warmPool.removeFirst()
                if (!candidate.delegate.dead && now - candidate.openedAtMs <= WARM_MAX_AGE_MS) {
                    picked = candidate
                    break
                } else {
                    expired.add(candidate.webSocket)
                }
            }
        }
        for (ws in expired) {
            runCatching { ws.close(1000, "stale") }
        }
        if (picked != null && warmPoolScope != null) {
            warmPoolScope?.launch(Dispatchers.IO) { refillWarmPool() }
        }
        return picked
    }

    private fun buildWsRequest(): Request {
        return Request.Builder()
            .url(endpoint.wsUrl)
            .header("Host", endpoint.effectiveHostHeader)
            .header("Sec-WebSocket-Protocol", WorkerCrypto.SUBPROTOCOL)
            .header("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36")
            .build()
    }

    fun openTunnel(
        targetHost: String,
        targetPort: Int,
        onWsOpened: () -> Unit = {},
        onReady: () -> Unit = {},
        onData: (ByteArray) -> Unit,
        onClosed: (reason: String?) -> Unit,
        onBytesSent: (Int) -> Unit = {},
        onBytesReceived: (Int) -> Unit = {}
    ): WorkerTunnelSession {
        val handshake = WorkerCrypto.buildInitHandshake(
            uuid = config.uuid.trim(),
            targetHost = targetHost,
            targetPort = targetPort,
            cmd = WorkerCrypto.CMD_TCP
        )

        val session = WorkerTunnelSession(
            handshake = handshake,
            onWsOpened = onWsOpened,
            onReady = onReady,
            onData = onData,
            onClosed = onClosed,
            onBytesSent = onBytesSent,
            onBytesReceived = onBytesReceived
        )

        // Fast-path: use a pre-warmed already-open WebSocket (0ms TCP+TLS+WS setup!)
        val warm = checkoutWarmSlot()
        if (warm != null && warm.delegate.attachTarget(session.listener)) {
            if (session.attachWarmOpenWebSocket(warm.webSocket)) {
                return session
            }
            warm.delegate.clearTarget()
            runCatching { warm.webSocket.close(1000, "retry") }
        }

        // Standard cold path
        val ws = okHttpClient.newWebSocket(buildWsRequest(), session.listener)
        session.attachWebSocket(ws)
        return session
    }

    /**
     * Resolves raw RFC 1035 DNS wire query via Local DNS-over-HTTPS (port 443 HTTP/2),
     * trying Cloudflare DoH through the user's Clean IP first, then direct Google DoH.
     */
    fun queryLocalDoh(dnsWireQuery: ByteArray): ByteArray? {
        if (isShutdown.get()) return null

        // 1) Cloudflare DoH over user's Clean IP (1-RTT port 443, immune to port 53 blocks)
        val cfAttempt = executeDohPost(
            client = dohCleanIpClient,
            url = "https://cloudflare-dns.com/dns-query",
            dnsWireQuery = dnsWireQuery
        )
        if (cfAttempt != null) return cfAttempt

        // 2) Fallback: Direct Google DoH (bypassed from VPN via self-bypass)
        return executeDohPost(
            client = dohDirectClient,
            url = "https://dns.google/dns-query",
            dnsWireQuery = dnsWireQuery
        )
    }

    private fun executeDohPost(
        client: OkHttpClient,
        url: String,
        dnsWireQuery: ByteArray
    ): ByteArray? {
        return try {
            val request = Request.Builder()
                .url(url)
                .header("Accept", "application/dns-message")
                .post(dnsWireQuery.toRequestBody(DNS_MESSAGE_MEDIA_TYPE))
                .build()
            client.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) return null
                resp.body?.bytes()?.takeIf { it.size >= 12 }
            }
        } catch (_: Exception) {
            null
        }
    }

    fun shutdown() {
        if (!isShutdown.compareAndSet(false, true)) return
        warmPoolJob?.cancel()
        warmPoolJob = null
        val socketsToClose = synchronized(poolLock) {
            val list = warmPool.map { it.webSocket }
            warmPool.clear()
            list
        }
        for (ws in socketsToClose) {
            runCatching { ws.close(1000, "shutdown") }
        }
        okHttpClient.dispatcher.cancelAll()
        okHttpClient.connectionPool.evictAll()
        okHttpClient.dispatcher.executorService.shutdown()
        dohCleanIpClient.dispatcher.cancelAll()
        dohCleanIpClient.connectionPool.evictAll()
        dohDirectClient.dispatcher.cancelAll()
        dohDirectClient.connectionPool.evictAll()
    }
}

class WorkerTunnelSession(
    private val handshake: WorkerCrypto.InitHandshake,
    private val onWsOpened: () -> Unit,
    private val onReady: () -> Unit,
    private val onData: (ByteArray) -> Unit,
    private val onClosed: (reason: String?) -> Unit,
    private val onBytesSent: (Int) -> Unit,
    private val onBytesReceived: (Int) -> Unit
) {
    private val lock = Any()
    private val pendingQueue = ArrayDeque<ByteArray>()
    private var pendingBytes = 0
    private val maxQueueBytes = 4 * 1024 * 1024

    @Volatile
    private var webSocket: WebSocket? = null

    @Volatile
    private var initSent = false

    @Volatile
    private var ackVerified = false

    private val closed = AtomicBoolean(false)

    val isOpen: Boolean
        get() = !closed.get() && initSent

    internal fun attachWebSocket(ws: WebSocket) {
        synchronized(lock) {
            webSocket = ws
            if (closed.get()) {
                ws.close(1000, "closed")
            }
        }
    }

    /**
     * Immediately activates an already-open pre-warmed WebSocket, sending Init and
     * flushing any queued 0-RTT payload in the same instant.
     */
    internal fun attachWarmOpenWebSocket(ws: WebSocket): Boolean {
        val toFlush: List<ByteArray>
        synchronized(lock) {
            if (closed.get()) return false
            webSocket = ws
            onWsOpened()
            if (!ws.send(handshake.packet.toByteString())) {
                webSocket = null
                return false
            }
            initSent = true
            toFlush = drainPendingLocked()
        }
        flushChunks(ws, toFlush)
        return true
    }

    /**
     * 0-RTT pipelined send: as soon as WebSocket is open and Init has been transmitted,
     * immediately sends XOR-encrypted data frames without waiting an extra RTT for the
     * worker's HMAC ACK (the worker queues them in st.q and drains right after dial()).
     */
    fun send(plaintext: ByteArray): Boolean {
        if (plaintext.isEmpty()) return true
        val wsToSend: WebSocket?
        synchronized(lock) {
            if (closed.get()) return false
            if (!initSent) {
                if (pendingBytes + plaintext.size > maxQueueBytes) {
                    closeInternal("صف ارسال پر شد")
                    return false
                }
                pendingQueue.addLast(plaintext)
                pendingBytes += plaintext.size
                return true
            }
            wsToSend = webSocket
        }
        val ws = wsToSend ?: return false
        val encrypted = WorkerCrypto.xorBytes(plaintext, handshake.key)
        val sent = ws.send(encrypted.toByteString())
        if (sent) {
            onBytesSent(plaintext.size)
        }
        return sent
    }

    fun close() {
        closeInternal(null)
    }

    private fun drainPendingLocked(): List<ByteArray> {
        if (pendingQueue.isEmpty()) return emptyList()
        val list = ArrayList<ByteArray>(pendingQueue.size)
        while (pendingQueue.isNotEmpty()) {
            list.add(pendingQueue.removeFirst())
        }
        pendingBytes = 0
        return list
    }

    private fun flushChunks(ws: WebSocket, chunks: List<ByteArray>) {
        for (chunk in chunks) {
            if (closed.get()) return
            val enc = WorkerCrypto.xorBytes(chunk, handshake.key)
            if (ws.send(enc.toByteString())) {
                onBytesSent(chunk.size)
            }
        }
    }

    private fun closeInternal(reason: String?) {
        if (!closed.compareAndSet(false, true)) return
        val wsToClose: WebSocket?
        synchronized(lock) {
            pendingQueue.clear()
            pendingBytes = 0
            wsToClose = webSocket
            webSocket = null
        }
        try {
            wsToClose?.close(1000, "done")
        } catch (_: Exception) {
        }
        onClosed(reason)
    }

    internal val listener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            val toFlush: List<ByteArray>
            synchronized(lock) {
                if (closed.get()) {
                    webSocket.close(1000, "cancelled")
                    return
                }
                if (initSent) return
                onWsOpened()
                if (!webSocket.send(handshake.packet.toByteString())) {
                    closeInternal("ارسال بسته Init ناموفق بود")
                    return
                }
                initSent = true
                toFlush = drainPendingLocked()
            }
            // Immediately pipeline queued 0-RTT data (e.g. TLS ClientHello) without waiting for ACK!
            flushChunks(webSocket, toFlush)
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            if (closed.get()) return
            val raw = bytes.toByteArray()
            if (!ackVerified) {
                if (!WorkerCrypto.verifyAck(raw, handshake.expectedAck)) {
                    closeInternal("تاییدیه HMAC-SHA256 ورکر نامعتبر است (UUID را بررسی کنید)")
                    return
                }
                ackVerified = true
                onReady()
                return
            }

            val decrypted = WorkerCrypto.xorBytes(raw, handshake.key)
            if (decrypted.isNotEmpty()) {
                onBytesReceived(decrypted.size)
                onData(decrypted)
            }
        }

        override fun onMessage(webSocket: WebSocket, text: String) = Unit

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            webSocket.close(1000, null)
            closeInternal(if (code == 1000) null else "WS closing ($code): $reason")
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            closeInternal(if (code == 1000) null else "WS closed ($code): $reason")
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            val httpCode = response?.code
            val detail = when {
                httpCode == 101 -> t.message
                httpCode != null -> "HTTP $httpCode (${response.message}) — آدرس ورکر یا Clean IP را بررسی کنید"
                else -> t.message ?: "خطای شبکه در اتصال WebSocket"
            }
            closeInternal(detail)
        }
    }
}
