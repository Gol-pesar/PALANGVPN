package com.example.vpn.protocol

import com.example.vpn.LogLevel
import com.example.vpn.VpnStateHolder
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import okhttp3.Dispatcher
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
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
import javax.net.SocketFactory

sealed interface HandshakeTestResult {
    data class Success(val latencyMs: Int, val resolvedIp: String) : HandshakeTestResult
    data class Failure(val reason: String) : HandshakeTestResult
}

/**
 * High-concurrency OkHttp WebSocket engine tuned for Cloudflare Worker tunneling:
 * - Uncaps OkHttp's default 5-per-host Dispatcher limit to 256 concurrent WebSocket dials
 * - Enables TCP_NODELAY and 128KB socket buffers on all outbound sockets
 * - Caches Clean IP / Worker DNS resolution to eliminate per-tunnel DNS lookup latency
 * - Uses non-Cloudflare target (www.gstatic.com:80) for ping tests so Workers dial directly
 *   without tripping Cloudflare-to-Cloudflare loopback blocks
 */
class WorkerWebSocketClient(
    private val config: WorkerConfig
) {
    private val endpoint: ParsedWorkerEndpoint =
        config.parseEndpoint() ?: throw IllegalArgumentException("Invalid Worker URL")

    @Volatile
    var lastResolvedIp: String = endpoint.cleanIpHost ?: endpoint.workerHost
        private set

    @Volatile
    private var cachedAddresses: List<InetAddress>? = null

    @Volatile
    private var cachedAtMs: Long = 0L

    private val customDns = object : Dns {
        override fun lookup(hostname: String): List<InetAddress> {
            val now = System.currentTimeMillis()
            val cached = cachedAddresses
            if (cached != null && now - cachedAtMs < 60_000L) {
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

        val request = Request.Builder()
            .url(endpoint.wsUrl)
            .header("Host", endpoint.effectiveHostHeader)
            .header("Sec-WebSocket-Protocol", WorkerCrypto.SUBPROTOCOL)
            .header("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36")
            .build()

        val session = WorkerTunnelSession(
            handshake = handshake,
            onWsOpened = onWsOpened,
            onReady = onReady,
            onData = onData,
            onClosed = onClosed,
            onBytesSent = onBytesSent,
            onBytesReceived = onBytesReceived
        )

        val ws = okHttpClient.newWebSocket(request, session.listener)
        session.attachWebSocket(ws)
        return session
    }

    fun shutdown() {
        okHttpClient.dispatcher.cancelAll()
        okHttpClient.connectionPool.evictAll()
        okHttpClient.dispatcher.executorService.shutdown()
    }

    companion object {
        /**
         * Performs a real end-to-end Worker WebSocket handshake + HMAC-SHA256 "OK" ACK check
         * dialing www.gstatic.com:80 (non-Cloudflare fast edge) so the Worker dials directly
         * without hitting Cloudflare-to-Cloudflare loopback blocks.
         */
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
    private var ackVerified = false

    private val closed = AtomicBoolean(false)

    val isOpen: Boolean
        get() = !closed.get() && ackVerified

    internal fun attachWebSocket(ws: WebSocket) {
        synchronized(lock) {
            webSocket = ws
            if (closed.get()) {
                ws.close(1000, "closed")
            }
        }
    }

    fun send(plaintext: ByteArray): Boolean {
        if (plaintext.isEmpty()) return true
        synchronized(lock) {
            if (closed.get()) return false
            if (!ackVerified) {
                if (pendingBytes + plaintext.size > maxQueueBytes) {
                    closeInternal("صف ارسال پر شد")
                    return false
                }
                pendingQueue.addLast(plaintext)
                pendingBytes += plaintext.size
                return true
            }
            val ws = webSocket ?: return false
            val encrypted = WorkerCrypto.xorBytes(plaintext, handshake.key)
            val sent = ws.send(encrypted.toByteString())
            if (sent) {
                onBytesSent(plaintext.size)
            }
            return sent
        }
    }

    fun close() {
        closeInternal(null)
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
            if (closed.get()) {
                webSocket.close(1000, "cancelled")
                return
            }
            onWsOpened()
            val sent = webSocket.send(handshake.packet.toByteString())
            if (!sent) {
                closeInternal("ارسال بسته Init ناموفق بود")
            }
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            if (closed.get()) return
            val raw = bytes.toByteArray()
            if (!ackVerified) {
                if (!WorkerCrypto.verifyAck(raw, handshake.expectedAck)) {
                    closeInternal("تاییدیه HMAC-SHA256 ورکر نامعتبر است (UUID را بررسی کنید)")
                    return
                }
                val toFlush = mutableListOf<ByteArray>()
                synchronized(lock) {
                    ackVerified = true
                    while (pendingQueue.isNotEmpty()) {
                        toFlush.add(pendingQueue.removeFirst())
                    }
                    pendingBytes = 0
                }
                onReady()
                for (chunk in toFlush) {
                    if (closed.get()) return
                    val enc = WorkerCrypto.xorBytes(chunk, handshake.key)
                    if (webSocket.send(enc.toByteString())) {
                        onBytesSent(chunk.size)
                    }
                }
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
