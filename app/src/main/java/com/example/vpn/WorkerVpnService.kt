package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.vpn.protocol.HandshakeTestResult
import com.example.vpn.protocol.WorkerConfig
import com.example.vpn.protocol.WorkerWebSocketClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicLong

class WorkerVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.example.vpn.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.example.vpn.ACTION_DISCONNECT"

        const val EXTRA_PROFILE_ID = "extra_profile_id"
        const val EXTRA_PROFILE_NAME = "extra_profile_name"
        const val EXTRA_WORKER_URL = "extra_worker_url"
        const val EXTRA_UUID = "extra_uuid"
        const val EXTRA_CLEAN_IP = "extra_clean_ip"
        const val EXTRA_SNI_SNIFFING = "extra_sni_sniffing"
        const val EXTRA_LOCAL_SOCKS = "extra_local_socks"
        const val EXTRA_LOCAL_SOCKS_PORT = "extra_local_socks_port"

        private const val NOTIFICATION_CHANNEL_ID = "edgetunnel_vpn_channel"
        private const val NOTIFICATION_ID = 1042

        fun createConnectIntent(context: Context, config: WorkerConfig): Intent {
            return Intent(context, WorkerVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_PROFILE_ID, config.profileId)
                putExtra(EXTRA_PROFILE_NAME, config.profileName)
                putExtra(EXTRA_WORKER_URL, config.workerUrl)
                putExtra(EXTRA_UUID, config.uuid)
                putExtra(EXTRA_CLEAN_IP, config.cleanIp)
                putExtra(EXTRA_SNI_SNIFFING, config.sniSniffingEnabled)
                putExtra(EXTRA_LOCAL_SOCKS, config.localSocksEnabled)
                putExtra(EXTRA_LOCAL_SOCKS_PORT, config.localSocksPort)
            }
        }

        fun createDisconnectIntent(context: Context): Intent {
            return Intent(context, WorkerVpnService::class.java).apply {
                action = ACTION_DISCONNECT
            }
        }
    }

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunInterface: ParcelFileDescriptor? = null
    private var tunOutputStream: FileOutputStream? = null
    private val tunWriteLock = Any()

    private var wsClient: WorkerWebSocketClient? = null
    private var tcpSessionManager: TcpSessionManager? = null
    private var dnsProxyHandler: DnsProxyHandler? = null
    private var localSocks5Server: LocalSocks5Server? = null

    private var packetLoopJob: Job? = null
    private var statsJob: Job? = null

    private val totalUploadBytes = AtomicLong(0L)
    private val totalDownloadBytes = AtomicLong(0L)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                VpnStateHolder.log(LogLevel.INFO, "درخواست قطع اتصال VPN دریافت شد")
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val config = WorkerConfig(
                    profileId = intent.getLongExtra(EXTRA_PROFILE_ID, 0L),
                    profileName = intent.getStringExtra(EXTRA_PROFILE_NAME).orEmpty().ifEmpty { "EdgeTunnel" },
                    workerUrl = intent.getStringExtra(EXTRA_WORKER_URL).orEmpty(),
                    uuid = intent.getStringExtra(EXTRA_UUID).orEmpty(),
                    cleanIp = intent.getStringExtra(EXTRA_CLEAN_IP).orEmpty(),
                    sniSniffingEnabled = intent.getBooleanExtra(EXTRA_SNI_SNIFFING, true),
                    localSocksEnabled = intent.getBooleanExtra(EXTRA_LOCAL_SOCKS, true),
                    localSocksPort = intent.getIntExtra(EXTRA_LOCAL_SOCKS_PORT, 10808)
                )
                startForegroundCompat(
                    title = getString(R.string.notification_title_connecting),
                    subtitle = config.profileName
                )
                serviceScope.launch {
                    startTunnel(config)
                }
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private suspend fun startTunnel(config: WorkerConfig) {
        stopTunnel(updateState = false)

        val validationError = config.validate()
        if (validationError != null) {
            VpnStateHolder.log(LogLevel.ERROR, validationError)
            VpnStateHolder.setState(VpnConnectionState.Error(validationError))
            stopSelf()
            return
        }

        val endpoint = config.parseEndpoint()
        if (endpoint == null) {
            VpnStateHolder.setState(VpnConnectionState.Error("Worker URL نامعتبر است"))
            stopSelf()
            return
        }

        VpnStateHolder.setState(VpnConnectionState.Connecting(config.profileName))
        VpnStateHolder.log(
            LogLevel.INFO,
            "شروع اتصال به ${endpoint.workerHost}:${endpoint.port}" +
                (endpoint.cleanIpHost?.let { " (Clean IP: $it)" } ?: " (Direct DNS)")
        )

        // Verify real Worker WebSocket + HMAC-SHA256 ACK handshake before switching device routes!
        when (val verifyResult = WorkerWebSocketClient.testHandshake(config)) {
            is HandshakeTestResult.Failure -> {
                VpnStateHolder.setState(VpnConnectionState.Error(verifyResult.reason))
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
            is HandshakeTestResult.Success -> {
                VpnStateHolder.log(
                    LogLevel.SUCCESS,
                    "تایید ورکر موفق (${verifyResult.latencyMs}ms) — راه‌اندازی رابط TUN…"
                )
            }
        }

        try {
            val builder = Builder()
                .setSession("EdgeTunnel - ${config.profileName}")
                .setMtu(1500)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")

            // Bypass our own app so OkHttp WebSocket connections to Worker / Clean IP never loop!
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                VpnStateHolder.log(LogLevel.WARN, "خطا در استثنا کردن اپلیکیشن: ${e.message}")
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            val pfd = builder.establish()
            if (pfd == null) {
                val msg = "ایجاد رابط TUN ناموفق بود (مجوز VPN بررسی شود)"
                VpnStateHolder.log(LogLevel.ERROR, msg)
                VpnStateHolder.setState(VpnConnectionState.Error(msg))
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }

            tunInterface = pfd
            tunOutputStream = FileOutputStream(pfd.fileDescriptor)
            totalUploadBytes.set(0L)
            totalDownloadBytes.set(0L)

            val client = WorkerWebSocketClient(config)
            wsClient = client

            val dnsHandler = DnsProxyHandler(
                scope = serviceScope,
                wsClient = client,
                writePacketToTun = ::writeToTun,
                onBytesSent = { totalUploadBytes.addAndGet(it.toLong()) },
                onBytesReceived = { totalDownloadBytes.addAndGet(it.toLong()) }
            )
            dnsProxyHandler = dnsHandler

            val tcpManager = TcpSessionManager(
                scope = serviceScope,
                wsClient = client,
                sniSniffingEnabled = config.sniSniffingEnabled,
                lookupDomain = dnsHandler::lookupDomainForIp,
                writePacketToTun = ::writeToTun,
                onBytesSent = { totalUploadBytes.addAndGet(it.toLong()) },
                onBytesReceived = { totalDownloadBytes.addAndGet(it.toLong()) }
            )
            tcpSessionManager = tcpManager

            var socksAddress: String? = null
            if (config.localSocksEnabled) {
                val socks = LocalSocks5Server(
                    port = config.localSocksPort,
                    scope = serviceScope,
                    wsClient = client,
                    onBytesSent = { totalUploadBytes.addAndGet(it.toLong()) },
                    onBytesReceived = { totalDownloadBytes.addAndGet(it.toLong()) }
                )
                if (socks.start()) {
                    localSocks5Server = socks
                    socksAddress = "127.0.0.1:${config.localSocksPort}"
                    VpnStateHolder.log(LogLevel.INFO, "پروکسی محلی SOCKS5 فعال شد: $socksAddress")
                }
            }

            val resolvedClean = endpoint.cleanIpHost ?: client.lastResolvedIp
            VpnStateHolder.setState(
                VpnConnectionState.Connected(
                    profileName = config.profileName,
                    workerHost = endpoint.workerHost,
                    cleanIp = resolvedClean
                )
            )
            startForegroundCompat(
                title = getString(R.string.notification_title_connected),
                subtitle = "${config.profileName} • $resolvedClean"
            )
            VpnStateHolder.log(LogLevel.SUCCESS, "تونل VPN فعال شد (MTU 1500 • DNS-over-Worker)")

            startStatsTicker(socksAddress)
            startPacketLoop(pfd, tcpManager, dnsHandler)
        } catch (e: Exception) {
            val msg = "خطا در راه‌اندازی تونل: ${e.message ?: "نامشخص"}"
            VpnStateHolder.log(LogLevel.ERROR, msg)
            VpnStateHolder.setState(VpnConnectionState.Error(msg))
            stopTunnel(updateState = false)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun startPacketLoop(
        pfd: ParcelFileDescriptor,
        tcpManager: TcpSessionManager,
        dnsHandler: DnsProxyHandler
    ) {
        packetLoopJob = serviceScope.launch(Dispatchers.IO) {
            val input = FileInputStream(pfd.fileDescriptor)
            val buffer = ByteArray(32_768)
            while (isActive) {
                val readLen = try {
                    input.read(buffer)
                } catch (_: Exception) {
                    break
                }
                if (readLen <= 0) continue

                val ip = PacketUtils.parseIpv4Header(buffer, readLen) ?: continue
                when (ip.protocol) {
                    PacketUtils.PROTOCOL_TCP -> {
                        val tcp = PacketUtils.parseTcpHeader(buffer, ip) ?: continue
                        tcpManager.handleTcpPacket(ip, tcp, buffer)
                    }
                    PacketUtils.PROTOCOL_UDP -> {
                        val udp = PacketUtils.parseUdpHeader(buffer, ip) ?: continue
                        if (udp.dstPort == 53) {
                            dnsHandler.handleUdpDnsPacket(ip, udp, buffer)
                        }
                    }
                }
            }
        }
    }

    private fun startStatsTicker(socksAddress: String?) {
        statsJob?.cancel()
        statsJob = serviceScope.launch(Dispatchers.IO) {
            var prevUp = 0L
            var prevDown = 0L
            while (isActive) {
                delay(1000L)
                val up = totalUploadBytes.get()
                val down = totalDownloadBytes.get()
                val upSpeed = (up - prevUp).coerceAtLeast(0L)
                val downSpeed = (down - prevDown).coerceAtLeast(0L)
                prevUp = up
                prevDown = down
                VpnStateHolder.updateStats(
                    uploadBytes = up,
                    downloadBytes = down,
                    uploadSpeedBps = upSpeed,
                    downloadSpeedBps = downSpeed,
                    activeTunnels = tcpSessionManager?.activeSessionCount ?: 0,
                    socksProxyAddress = socksAddress
                )
            }
        }
    }

    private fun writeToTun(packet: ByteArray) {
        synchronized(tunWriteLock) {
            try {
                tunOutputStream?.write(packet)
            } catch (_: Exception) {
            }
        }
    }

    private fun stopTunnel(updateState: Boolean = true) {
        packetLoopJob?.cancel()
        packetLoopJob = null
        statsJob?.cancel()
        statsJob = null

        localSocks5Server?.stop()
        localSocks5Server = null

        tcpSessionManager?.closeAll()
        tcpSessionManager = null
        dnsProxyHandler = null

        wsClient?.shutdown()
        wsClient = null

        synchronized(tunWriteLock) {
            try { tunOutputStream?.close() } catch (_: Exception) {}
            tunOutputStream = null
        }
        try { tunInterface?.close() } catch (_: Exception) {}
        tunInterface = null

        if (updateState) {
            VpnStateHolder.setState(VpnConnectionState.Disconnected)
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    override fun onRevoke() {
        VpnStateHolder.log(LogLevel.WARN, "دسترسی VPN توسط سیستم لغو شد")
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startForegroundCompat(title: String, subtitle: String) {
        ensureNotificationChannel()
        val notification = buildNotification(title, subtitle)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            val existing = manager.getNotificationChannel(NOTIFICATION_CHANNEL_ID)
            if (existing == null) {
                val channel = NotificationChannel(
                    NOTIFICATION_CHANNEL_ID,
                    getString(R.string.notification_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = getString(R.string.notification_channel_desc)
                    setShowBadge(false)
                }
                manager.createNotificationChannel(channel)
            }
        }
    }

    private fun buildNotification(title: String, subtitle: String): Notification {
        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = PendingIntent.getService(
            this,
            1,
            createDisconnectIntent(this),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openAppIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.notification_action_disconnect),
                disconnectIntent
            )
            .build()
    }
}
