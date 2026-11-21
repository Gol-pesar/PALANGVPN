package com.example.ui

import android.app.Application
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.AppDatabase
import com.example.data.ProfileRepository
import com.example.data.ServerProfileEntity
import com.example.data.SettingsDataStore
import com.example.data.TunnelSettings
import com.example.ui.components.InstalledAppInfo
import com.example.vpn.LogLevel
import com.example.vpn.VpnConnectionState
import com.example.vpn.VpnLogEntry
import com.example.vpn.VpnStateHolder
import com.example.vpn.VpnTrafficStats
import com.example.vpn.protocol.HandshakeTestResult
import com.example.vpn.protocol.WorkerConfig
import com.example.vpn.protocol.WorkerWebSocketClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.UUID

data class ProfileEditorState(
    val isOpen: Boolean = false,
    val editingId: Long = 0L,
    val name: String = "",
    val workerUrl: String = "",
    val uuid: String = ProfileRepository.WORKER_DEFAULT_UUID,
    val cleanIp: String = "",
    val errorMessage: String? = null
)

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = ProfileRepository(
        dao = AppDatabase.getInstance(application).profileDao(),
        settingsStore = SettingsDataStore(application)
    )

    val profiles: StateFlow<List<ServerProfileEntity>> = repository.profiles.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = emptyList()
    )

    val selectedProfile: StateFlow<ServerProfileEntity?> = repository.selectedProfile.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = null
    )

    val settings: StateFlow<TunnelSettings> = repository.settings.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = TunnelSettings()
    )

    val connectionState: StateFlow<VpnConnectionState> = VpnStateHolder.connectionState
    val trafficStats: StateFlow<VpnTrafficStats> = VpnStateHolder.stats
    val logs: StateFlow<List<VpnLogEntry>> = VpnStateHolder.logs

    private val _testingProfileIds = MutableStateFlow<Set<Long>>(emptySet())
    val testingProfileIds: StateFlow<Set<Long>> = _testingProfileIds.asStateFlow()

    private val _editorState = MutableStateFlow(ProfileEditorState())
    val editorState: StateFlow<ProfileEditorState> = _editorState.asStateFlow()

    private val _perAppSheetOpen = MutableStateFlow(false)
    val perAppSheetOpen: StateFlow<Boolean> = _perAppSheetOpen.asStateFlow()

    private val _installedApps = MutableStateFlow<List<InstalledAppInfo>>(emptyList())
    val installedApps: StateFlow<List<InstalledAppInfo>> = _installedApps.asStateFlow()

    private val _loadingApps = MutableStateFlow(false)
    val loadingApps: StateFlow<Boolean> = _loadingApps.asStateFlow()

    private val _events = MutableSharedFlow<String>(extraBufferCapacity = 8)
    val events: SharedFlow<String> = _events.asSharedFlow()

    init {
        viewModelScope.launch(Dispatchers.IO) {
            repository.ensureDefaultProfile()
        }
    }

    fun buildActiveWorkerConfig(): Pair<WorkerConfig?, String?> {
        val profile = selectedProfile.value
            ?: return null to "ابتدا یک پروفایل ورکر ایجاد کنید"
        val currentSettings = settings.value
        val selfPkg = getApplication<Application>().packageName
        val config = WorkerConfig(
            profileId = profile.id,
            profileName = profile.name,
            workerUrl = profile.workerUrl,
            uuid = profile.uuid,
            cleanIp = profile.cleanIp,
            fakeDnsEnabled = currentSettings.fakeDnsEnabled,
            localDnsEnabled = currentSettings.localDnsEnabled,
            sniSniffingEnabled = currentSettings.sniSniffingEnabled,
            localSocksEnabled = currentSettings.localSocksEnabled,
            localSocksPort = currentSettings.localSocksPort,
            perAppEnabled = currentSettings.perAppEnabled,
            perAppBypassMode = currentSettings.perAppBypassMode,
            perAppPackages = currentSettings.perAppPackages - selfPkg
        )
        val validationError = config.validate()
        if (validationError != null) {
            return null to validationError
        }
        return config to null
    }

    fun selectProfile(profileId: Long) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.selectProfile(profileId)
        }
    }

    fun openCreateProfileEditor() {
        _editorState.value = ProfileEditorState(
            isOpen = true,
            editingId = 0L,
            name = "",
            workerUrl = "",
            uuid = ProfileRepository.WORKER_DEFAULT_UUID,
            cleanIp = "",
            errorMessage = null
        )
    }

    fun openEditProfileEditor(profile: ServerProfileEntity) {
        _editorState.value = ProfileEditorState(
            isOpen = true,
            editingId = profile.id,
            name = profile.name,
            workerUrl = profile.workerUrl,
            uuid = profile.uuid,
            cleanIp = profile.cleanIp,
            errorMessage = null
        )
    }

    fun closeEditor() {
        _editorState.update { it.copy(isOpen = false, errorMessage = null) }
    }

    fun updateEditorName(value: String) = _editorState.update { it.copy(name = value, errorMessage = null) }
    fun updateEditorWorkerUrl(value: String) = _editorState.update { it.copy(workerUrl = value, errorMessage = null) }
    fun updateEditorUuid(value: String) = _editorState.update { it.copy(uuid = value, errorMessage = null) }
    fun updateEditorCleanIp(value: String) = _editorState.update { it.copy(cleanIp = value, errorMessage = null) }

    fun generateRandomUuidInEditor() {
        _editorState.update { it.copy(uuid = UUID.randomUUID().toString(), errorMessage = null) }
    }

    fun saveEditorProfile() {
        val state = _editorState.value
        val candidate = WorkerConfig(
            workerUrl = state.workerUrl,
            uuid = state.uuid,
            cleanIp = state.cleanIp
        )
        val validationError = candidate.validate()
        if (validationError != null) {
            _editorState.update { it.copy(errorMessage = validationError) }
            return
        }

        val derivedName = state.name.trim().ifEmpty {
            candidate.parseEndpoint()?.workerHost?.substringBefore('.')?.replaceFirstChar { it.uppercase() }
                ?: "ورکر من"
        }

        viewModelScope.launch(Dispatchers.IO) {
            repository.saveProfile(
                ServerProfileEntity(
                    id = state.editingId,
                    name = derivedName,
                    workerUrl = state.workerUrl.trim(),
                    uuid = state.uuid.trim(),
                    cleanIp = state.cleanIp.trim()
                ),
                selectAfterSave = true
            )
            _editorState.update { it.copy(isOpen = false, errorMessage = null) }
            _events.tryEmit("پروفایل «$derivedName» ذخیره شد")
        }
    }

    fun deleteProfile(profile: ServerProfileEntity) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.deleteProfile(profile.id)
            _events.tryEmit("پروفایل «${profile.name}» حذف شد")
        }
    }

    fun testProfileHandshake(profile: ServerProfileEntity) {
        if (_testingProfileIds.value.contains(profile.id)) return
        val config = WorkerConfig(
            profileId = profile.id,
            profileName = profile.name,
            workerUrl = profile.workerUrl,
            uuid = profile.uuid,
            cleanIp = profile.cleanIp
        )
        val validationError = config.validate()
        if (validationError != null) {
            _events.tryEmit(validationError)
            return
        }

        _testingProfileIds.update { it + profile.id }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                when (val result = WorkerWebSocketClient.testHandshake(config)) {
                    is HandshakeTestResult.Success -> {
                        repository.updateLatency(profile.id, result.latencyMs)
                        _events.tryEmit("اتصال موفق: ${result.latencyMs}ms (${result.resolvedIp})")
                    }
                    is HandshakeTestResult.Failure -> {
                        repository.updateLatency(profile.id, null)
                        _events.tryEmit("تست ناموفق: ${result.reason}")
                    }
                }
            } finally {
                _testingProfileIds.update { it - profile.id }
            }
        }
    }

    fun exportProfileUri(profile: ServerProfileEntity): String {
        return repository.exportProfileUri(profile)
    }

    fun importProfileFromClipboard(clipboardText: String) {
        val parsed = repository.parseProfileUri(clipboardText)
        if (parsed == null) {
            _events.tryEmit("لینک معتبر edgetunnel:// در کلیپ‌بورد یافت نشد")
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            repository.saveProfile(parsed, selectAfterSave = true)
            _events.tryEmit("پروفایل «${parsed.name}» وارد شد")
        }
    }

    fun setFakeDnsEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setFakeDnsEnabled(enabled)
            VpnStateHolder.log(
                LogLevel.INFO,
                if (enabled) "Fake DNS (198.18.0.0/15) فعال شد" else "Fake DNS غیرفعال شد"
            )
        }
    }

    fun setLocalDnsEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setLocalDnsEnabled(enabled)
            VpnStateHolder.log(
                LogLevel.INFO,
                if (enabled) "Local DNS (DoH 443) فعال شد" else "Local DNS غیرفعال شد"
            )
        }
    }

    fun setSniSniffingEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setSniSniffingEnabled(enabled)
            VpnStateHolder.log(
                LogLevel.INFO,
                if (enabled) "تشخیص هوشمند TLS SNI فعال شد" else "تشخیص هوشمند TLS SNI غیرفعال شد"
            )
        }
    }

    fun setLocalSocksEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setLocalSocksEnabled(enabled)
            VpnStateHolder.log(
                LogLevel.INFO,
                if (enabled) "پروکسی محلی SOCKS5 فعال شد" else "پروکسی محلی SOCKS5 غیرفعال شد"
            )
        }
    }

    fun setPerAppEnabled(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setPerAppEnabled(enabled)
            VpnStateHolder.log(
                LogLevel.INFO,
                if (enabled) "Per-App Proxy فعال شد (در اتصال بعدی اعمال می‌شود)" else "Per-App Proxy غیرفعال شد"
            )
        }
    }

    fun setPerAppBypassMode(bypassMode: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setPerAppBypassMode(bypassMode)
        }
    }

    fun togglePerAppPackage(packageName: String) {
        val selfPkg = getApplication<Application>().packageName
        if (packageName == selfPkg) return
        viewModelScope.launch(Dispatchers.IO) {
            repository.togglePerAppPackage(packageName)
        }
    }

    fun clearPerAppSelection() {
        viewModelScope.launch(Dispatchers.IO) {
            repository.setPerAppPackages(emptySet())
        }
    }

    fun openPerAppPicker() {
        _perAppSheetOpen.value = true
        if (_installedApps.value.isEmpty() && !_loadingApps.value) {
            loadLaunchableApps()
        }
    }

    fun closePerAppPicker() {
        _perAppSheetOpen.value = false
    }

    private fun loadLaunchableApps() {
        _loadingApps.value = true
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val app = getApplication<Application>()
                val pm = app.packageManager
                val selfPkg = app.packageName
                val launcherIntent = Intent(Intent.ACTION_MAIN).apply {
                    addCategory(Intent.CATEGORY_LAUNCHER)
                }
                val resolved = pm.queryIntentActivities(launcherIntent, PackageManager.MATCH_ALL)
                val uniqueApps = LinkedHashMap<String, InstalledAppInfo>()
                for (info in resolved) {
                    val pkg = info.activityInfo?.packageName ?: continue
                    // Always exclude EdgeTunnel itself — it is permanently self-bypassed
                    if (pkg == selfPkg || uniqueApps.containsKey(pkg)) continue
                    val label = info.loadLabel(pm)?.toString()?.trim().orEmpty().ifEmpty { pkg }
                    val bitmap = runCatching {
                        info.loadIcon(pm)?.toBitmap(width = 72, height = 72)
                    }.getOrNull()
                    uniqueApps[pkg] = InstalledAppInfo(
                        packageName = pkg,
                        label = label,
                        iconBitmap = bitmap
                    )
                }
                _installedApps.value = uniqueApps.values.sortedBy { it.label.lowercase() }
            } catch (_: Exception) {
                _installedApps.value = emptyList()
            } finally {
                _loadingApps.value = false
            }
        }
    }

    fun clearLogs() {
        VpnStateHolder.clearLogs()
    }

    fun emitMessage(msg: String) {
        _events.tryEmit(msg)
    }
}
