package com.example.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

sealed interface VpnConnectionState {
    data object Disconnected : VpnConnectionState
    data class Connecting(val profileName: String) : VpnConnectionState
    data class Connected(val profileName: String, val workerHost: String, val cleanIp: String) : VpnConnectionState
    data class Error(val message: String) : VpnConnectionState
}

enum class LogLevel { INFO, SUCCESS, WARN, ERROR }

data class VpnLogEntry(
    val id: Long,
    val timestamp: String,
    val level: LogLevel,
    val message: String
)

data class VpnTrafficStats(
    val uploadBytes: Long = 0L,
    val downloadBytes: Long = 0L,
    val uploadSpeedBps: Long = 0L,
    val downloadSpeedBps: Long = 0L,
    val activeTunnels: Int = 0,
    val connectedSinceMs: Long? = null,
    val socksProxyAddress: String? = null
)

object VpnStateHolder {
    private const val MAX_LOGS = 200
    private var logSequence = 0L

    private val _connectionState = MutableStateFlow<VpnConnectionState>(VpnConnectionState.Disconnected)
    val connectionState: StateFlow<VpnConnectionState> = _connectionState.asStateFlow()

    private val _stats = MutableStateFlow(VpnTrafficStats())
    val stats: StateFlow<VpnTrafficStats> = _stats.asStateFlow()

    private val _logs = MutableStateFlow<List<VpnLogEntry>>(emptyList())
    val logs: StateFlow<List<VpnLogEntry>> = _logs.asStateFlow()

    fun setState(state: VpnConnectionState) {
        _connectionState.value = state
        when (state) {
            is VpnConnectionState.Connected -> {
                _stats.update {
                    it.copy(connectedSinceMs = it.connectedSinceMs ?: System.currentTimeMillis())
                }
            }
            is VpnConnectionState.Disconnected, is VpnConnectionState.Error -> {
                _stats.value = VpnTrafficStats()
            }
            is VpnConnectionState.Connecting -> {
                _stats.value = VpnTrafficStats()
            }
        }
    }

    fun updateStats(
        uploadBytes: Long,
        downloadBytes: Long,
        uploadSpeedBps: Long,
        downloadSpeedBps: Long,
        activeTunnels: Int,
        socksProxyAddress: String?
    ) {
        _stats.update { current ->
            current.copy(
                uploadBytes = uploadBytes,
                downloadBytes = downloadBytes,
                uploadSpeedBps = uploadSpeedBps,
                downloadSpeedBps = downloadSpeedBps,
                activeTunnels = activeTunnels,
                socksProxyAddress = socksProxyAddress
            )
        }
    }

    fun log(level: LogLevel, message: String) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val entry = VpnLogEntry(
            id = ++logSequence,
            timestamp = time,
            level = level,
            message = message
        )
        _logs.update { current ->
            val updated = current + entry
            if (updated.size > MAX_LOGS) updated.takeLast(MAX_LOGS) else updated
        }
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }
}
