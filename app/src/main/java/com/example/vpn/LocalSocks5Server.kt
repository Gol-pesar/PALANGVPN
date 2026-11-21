package com.example.vpn

import com.example.vpn.protocol.WorkerWebSocketClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Lightweight loopback-only RFC 1928 SOCKS5 proxy (127.0.0.1:10808) backed by the
 * same Worker WebSocket tunnel engine.
 */
class LocalSocks5Server(
    private val port: Int,
    private val scope: CoroutineScope,
    private val wsClient: WorkerWebSocketClient,
    private val onBytesSent: (Int) -> Unit,
    private val onBytesReceived: (Int) -> Unit
) {
    private var serverSocket: ServerSocket? = null
    private var acceptJob: Job? = null
    private val running = AtomicBoolean(false)

    fun start(): Boolean {
        if (!running.compareAndSet(false, true)) return true
        return try {
            val ss = ServerSocket(port, 64, InetAddress.getByName("127.0.0.1"))
            serverSocket = ss
            acceptJob = scope.launch(Dispatchers.IO) {
                while (isActive && running.get()) {
                    val client = try {
                        ss.accept()
                    } catch (_: Exception) {
                        break
                    }
                    launch(Dispatchers.IO) { handleClient(client) }
                }
            }
            true
        } catch (e: Exception) {
            running.set(false)
            VpnStateHolder.log(LogLevel.WARN, "پروکسی محلی SOCKS5 روی پورت $port باز نشد: ${e.message}")
            false
        }
    }

    fun stop() {
        running.set(false)
        acceptJob?.cancel()
        acceptJob = null
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null
    }

    private fun handleClient(socket: Socket) {
        try {
            socket.tcpNoDelay = true
            val input = DataInputStream(BufferedInputStream(socket.getInputStream()))
            val output = socket.getOutputStream()

            // Greeting: VER(1), NMETHODS(1), METHODS(N)
            val ver = input.readUnsignedByte()
            if (ver != 0x05) {
                socket.close()
                return
            }
            val nMethods = input.readUnsignedByte()
            val methods = ByteArray(nMethods)
            input.readFully(methods)
            // Reply: VER=5, METHOD=0 (NO AUTH)
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // Request: VER(1), CMD(1), RSV(1), ATYP(1), DST.ADDR, DST.PORT(2)
            val reqVer = input.readUnsignedByte()
            val cmd = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val atyp = input.readUnsignedByte()

            if (reqVer != 0x05 || cmd != 0x01) {
                output.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                output.flush()
                socket.close()
                return
            }

            val host = when (atyp) {
                0x01 -> {
                    val addr = ByteArray(4)
                    input.readFully(addr)
                    InetAddress.getByAddress(addr).hostAddress ?: ""
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
            if (host.isBlank() || dstPort !in 1..65535) {
                socket.close()
                return
            }

            val tunnelClosed = AtomicBoolean(false)
            val session = wsClient.openTunnel(
                targetHost = host,
                targetPort = dstPort,
                onReady = {
                    try {
                        output.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        output.flush()
                    } catch (_: Exception) {
                        tunnelClosed.set(true)
                        try { socket.close() } catch (_: Exception) {}
                    }
                },
                onData = { data ->
                    try {
                        output.write(data)
                        output.flush()
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

            val buffer = ByteArray(16 * 1024)
            while (!tunnelClosed.get() && running.get()) {
                val read = input.read(buffer)
                if (read <= 0) break
                val chunk = buffer.copyOf(read)
                if (!session.send(chunk)) break
            }
            session.close()
        } catch (_: Exception) {
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }
}
