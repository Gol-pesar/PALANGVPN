package com.example.data

import android.net.Uri
import kotlinx.coroutines.flow.Flow

class ProfileRepository(
    private val dao: ProfileDao,
    private val settingsStore: SettingsDataStore
) {
    companion object {
        const val WORKER_DEFAULT_UUID = "63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd"
    }

    val profiles: Flow<List<ServerProfileEntity>> = dao.observeProfiles()
    val selectedProfile: Flow<ServerProfileEntity?> = dao.observeSelectedProfile()
    val settings: Flow<TunnelSettings> = settingsStore.settingsFlow

    suspend fun ensureDefaultProfile() {
        if (dao.countProfiles() == 0) {
            dao.insert(
                ServerProfileEntity(
                    name = "ورکر پیش‌فرض",
                    workerUrl = "",
                    uuid = WORKER_DEFAULT_UUID,
                    cleanIp = "",
                    isSelected = true
                )
            )
        } else if (dao.getSelectedProfileOnce() == null) {
            dao.getMostRecentProfile()?.let { dao.selectProfile(it.id) }
        }
    }

    suspend fun saveProfile(profile: ServerProfileEntity, selectAfterSave: Boolean = true): Long {
        val cleaned = profile.copy(
            name = profile.name.trim().ifEmpty { "ورکر جدید" },
            workerUrl = profile.workerUrl.trim(),
            uuid = profile.uuid.trim(),
            cleanIp = profile.cleanIp.trim(),
            updatedAt = System.currentTimeMillis()
        )
        val id = if (cleaned.id == 0L) {
            dao.insert(cleaned)
        } else {
            dao.update(cleaned)
            cleaned.id
        }
        if (selectAfterSave) {
            dao.selectProfile(id)
        }
        return id
    }

    suspend fun selectProfile(id: Long) {
        dao.selectProfile(id)
    }

    suspend fun updateLatency(id: Long, latencyMs: Int?) {
        dao.updateLatency(id, latencyMs)
    }

    suspend fun deleteProfile(id: Long) {
        dao.deleteById(id)
        if (dao.getSelectedProfileOnce() == null) {
            dao.getMostRecentProfile()?.let { dao.selectProfile(it.id) }
        }
    }

    suspend fun setSniSniffingEnabled(enabled: Boolean) = settingsStore.setSniSniffingEnabled(enabled)

    suspend fun setLocalSocksEnabled(enabled: Boolean) = settingsStore.setLocalSocksEnabled(enabled)

    fun exportProfileUri(profile: ServerProfileEntity): String {
        return Uri.Builder()
            .scheme("edgetunnel")
            .authority("worker")
            .appendQueryParameter("name", profile.name)
            .appendQueryParameter("url", profile.workerUrl)
            .appendQueryParameter("uuid", profile.uuid)
            .appendQueryParameter("ip", profile.cleanIp)
            .build()
            .toString()
    }

    fun parseProfileUri(raw: String): ServerProfileEntity? {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("edgetunnel://", ignoreCase = true)) return null
        val uri = runCatching { Uri.parse(trimmed) }.getOrNull() ?: return null
        val url = uri.getQueryParameter("url")?.trim().orEmpty()
        val uuid = uri.getQueryParameter("uuid")?.trim().orEmpty()
        if (url.isEmpty() && uuid.isEmpty()) return null
        val name = uri.getQueryParameter("name")?.trim().orEmpty().ifEmpty { "پروفایل واردشده" }
        val cleanIp = uri.getQueryParameter("ip")?.trim().orEmpty()
        return ServerProfileEntity(
            name = name,
            workerUrl = url,
            uuid = uuid.ifEmpty { WORKER_DEFAULT_UUID },
            cleanIp = cleanIp
        )
    }
}
