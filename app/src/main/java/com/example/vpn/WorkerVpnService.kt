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
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
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
        const val EXTRA_FAKE_DNS = "extra_fake_dns"
        const val EXTRA_LOCAL_DNS = "extra_local_dns"
        const val EXTRA_SNI_SNIFFING = "extra_sni_sniffing"
        const val EXTRA_LOCAL_SOCKS = "extra_local_socks"
        const val EXTRA_LOCAL_SOCKS_PORT = "extra_local_socks_port"
        const val EXTRA_PER_APP_ENABLED = "extra_per_app_enabled"
        const val EXTRA_PER_APP_BYPASS_MODE = "extra_per_app_bypass_mode"
        const val EXTRA_PER_APP_PACKAGES = "extra_per_app_packages"

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
                putExtra(EXTRA_FAKE_DNS, config.fakeDnsEnabled)
                putExtra(EXTRA_LOCAL_DNS, config.localDnsEnabled)
                putExtra(EXTRA_SNI_SNIFFING, config.sniSniffingEnabled)
                putExtra(EXTRA_LOCAL_SOCKS, config.localSocksEnabled)
                putExtra(EXTRA_LOCAL_SOCKS_PORT, config.localSocksPort)
                putExtra(EXTRA_PER_APP_ENABLED, config.perAppEnabled)
                putExtra(EXTRA_PER_APP_BYPASS_MODE, config.perAppBypassMode)
                putStringArrayListExtra(EXTRA_PER_APP_PACKAGES, ArrayList(config.perAppPackages))
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
    private val tunWriteQueue = ArrayBlockingQueue<ByteArray>(4096)
    private val tunRunning = AtomicBoolean(false)

    private var wsClient: WorkerWebSocketClient? = null
    private var tcpSessionManager: TcpSessionManager? = null
    private var dnsProxyHandler: DnsProxyHandler? = null
    private var localSocks5Server: LocalSocks5Server? = null

    private var packetLoopJob: Job? = null
    private var tunWriterJob: Job? = null
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
                val perAppList = intent.getStringArrayListExtra(EXTRA_PER_APP_PACKAGES)?.toSet() ?: emptySet()
                val config = WorkerConfig(
                    profileId = intent.getLongExtra(EXTRA_PROFILE_ID, 0L),
                    profileName = intent.getStringExtra(EXTRA_PROFILE_NAME).orEmpty().ifEmpty { "EdgeTunnel" },
                    workerUrl = intent.getStringExtra(EXTRA_WORKER_URL).orEmpty(),
                    uuid = intent.getStringExtra(EXTRA_UUID).orEmpty(),
                    cleanIp = intent.getStringExtra(EXTRA_CLEAN_IP).orEmpty(),
                    fakeDnsEnabled = intent.getBooleanExtra(EXTRA_FAKE_DNS, true),
                    localDnsEnabled = intent.getBooleanExtra(EXTRA_LOCAL_DNS, true),
                    sniSniffingEnabled = intent.getBooleanExtra(EXTRA_SNI_SNIFFING, true),
                    localSocksEnabled = intent.getBooleanExtra(EXTRA_LOCAL_SOCKS, true),
                    localSocksPort = intent.getIntExtra(EXTRA_LOCAL_SOCKS_PORT, 10808),
                    perAppEnabled = intent.getBooleanExtra(EXTRA_PER_APP_ENABLED, false),
                    perAppBypassMode = intent.getBooleanExtra(EXTRA_PER_APP_BYPASS_MODE, true),
                    perAppPackages = perAppList
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
                .addDnsServer("8.8.8.8")

            // Apply Per-App Proxy & strictly enforce Self-Bypass so EdgeTunnel NEVER loops into itself!
            applyPerAppRoutingAndSelfBypass(builder, config)

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
            tunWriteQueue.clear()
            tunRunning.set(true)
            totalUploadBytes.set(0L)
            totalDownloadBytes.set(0L)

            startTunWriterLoop(tunOutputStream!!)

            val client = WorkerWebSocketClient(config)
            wsClient = client
            // Pre-warm 4 idle TLS+WebSocket connections immediately for 0ms checkout!
            client.startWarmPool(serviceScope)

            val dnsHandler = DnsProxyHandler(
                scope = serviceScope,
                wsClient = client,
                fakeDnsEnabled = config.fakeDnsEnabled,
                localDnsEnabled = config.localDnsEnabled,
                writePacketToTun = ::enqueueTunWrite,
                onBytesSent = { totalUploadBytes.addAndGet(it.toLong()) },
                onBytesReceived = { totalDownloadBytes.addAndGet(it.toLong()) }
            )
            dnsProxyHandler = dnsHandler
            dnsHandler.prewarm()

            val tcpManager = TcpSessionManager(
                scope = serviceScope,
                wsClient = client,
                sniSniffingEnabled = config.sniSniffingEnabled,
                lookupDomain = dnsHandler::lookupDomainForIp,
                writePacketToTun = ::enqueueTunWrite,
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

            val dnsSummary = buildList {
                if (config.fakeDnsEnabled) add("FakeDNS")
                if (config.localDnsEnabled) add("LocalDNS(DoH)")
                if (isEmpty()) add("RemoteDNS")
            }.joinToString("+")

            VpnStateHolder.log(
                LogLevel.SUCCESS,
                "تونل فعال شد (WarmPool 0-RTT • NewReno TCP • $dnsSummary • Self-Bypass)"
            )

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

    /**
     * Strictly bypasses this app itself (Self-Bypass) in every configuration and applies
     * Per-App Proxy rules (either Disallowed/Bypass list or Allowed-Only list).
     */
    private fun applyPerAppRoutingAndSelfBypass(builder: Builder, config: WorkerConfig) {
        val selfPkg = packageName
        val filteredPackages = config.perAppPackages
            .map { it.trim() }
            .filter { it.isNotEmpty() && it != selfPkg }

        if (config.perAppEnabled && !config.perAppBypassMode && filteredPackages.isNotEmpty()) {
            // Allowed-Only mode: route ONLY selected apps; selfPkg is strictly excluded -> auto-bypassed!
            var added = 0
            for (pkg in filteredPackages) {
                try {
                    builder.addAllowedApplication(pkg)
                    added++
                } catch (_: Exception) {
                }
            }
            if (added > 0) {
                VpnStateHolder.log(
                    LogLevel.INFO,
                    "Per-App Proxy (فقط انتخابی): $added برنامه از تونل عبور می‌کند (Self-Bypass فعال)"
                )
                return
            }
        }

        // Default or Bypass mode: ALWAYS disallow selfPkg first!
        try {
            builder.addDisallowedApplication(selfPkg)
            VpnStateHolder.log(LogLevel.INFO, "بایپس خودکار اپلیکیشن (Self-Bypass): $selfPkg")
        } catch (e: Exception) {
            VpnStateHolder.log(LogLevel.WARN, "خطا در Self-Bypass: ${e.message}")
        }

        if (config.perAppEnabled && config.perAppBypassMode && filteredPackages.isNotEmpty()) {
            var bypassed = 0
            for (pkg in filteredPackages) {
                try {
                    builder.addDisallowedApplication(pkg)
                    bypassed++
                } catch (_: Exception) {
                }
            }
            VpnStateHolder.log(
                LogLevel.INFO,
                "Per-App Proxy (حالت بایپس): $bypassed برنامه + خود اپلیکیشن مستثنا شدند"
            )
        }
    }

    private fun startTunWriterLoop(output: FileOutputStream) {
        tunWriterJob?.cancel()
        tunWriterJob = serviceScope.launch(Dispatchers.IO) {
            while (isActive && tunRunning.get()) {
                val packet = try {
                    tunWriteQueue.poll(100, TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    break
                } ?: continue

                try {
                    output.write(packet)
                } catch (_: Exception) {
                    if (!tunRunning.get()) break
                }
            }
        }
    }

    private fun enqueueTunWrite(packet: ByteArray) {
        if (!tunRunning.get()) return
        tunWriteQueue.offer(packet)
    }

    private fun startPacketLoop(
        pfd: ParcelFileDescriptor,
        tcpManager: TcpSessionManager,
        dnsHandler: DnsProxyHandler
    ) {
        packetLoopJob = serviceScope.launch(Dispatchers.IO) {
            val input = FileInputStream(pfd.fileDescriptor)
            val buffer = ByteArray(32_768)
            while (isActive && tunRunning.get()) {
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
                        } else {
                            // Instantly reject UDP/443 (QUIC) & non-DNS UDP with ICMP Port Unreachable
                            val icmpUnreachable = PacketUtils.buildIpv4IcmpPortUnreachable(buffer, ip)
                            enqueueTunWrite(icmpUnreachable)
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

    private fun stopTunnel(updateState: Boolean = true) {
        tunRunning.set(false)
        packetLoopJob?.cancel()
        packetLoopJob = null
        tunWriterJob?.cancel()
        tunWriterJob = null
        statsJob?.cancel()
        statsJob = null

        localSocks5Server?.stop()
        localSocks5Server = null

        tcpSessionManager?.closeAll()
        tcpSessionManager = null

        dnsProxyHandler?.close()
        dnsProxyHandler = null

        wsClient?.shutdown()
        wsClient = null

        tunWriteQueue.clear()
        try { tunOutputStream?.close() } catch (_: Exception) {}
        tunOutputStream = null
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
