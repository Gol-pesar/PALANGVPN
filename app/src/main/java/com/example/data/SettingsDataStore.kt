package com.example.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.tunnelSettingsStore: DataStore<Preferences> by preferencesDataStore(
    name = "edgetunnel_settings"
)

data class TunnelSettings(
    val fakeDnsEnabled: Boolean = true,
    val localDnsEnabled: Boolean = true,
    val sniSniffingEnabled: Boolean = true,
    val localSocksEnabled: Boolean = true,
    val localSocksPort: Int = 10808,
    val perAppEnabled: Boolean = false,
    val perAppBypassMode: Boolean = true, // true = bypass selected apps, false = proxy ONLY selected apps
    val perAppPackages: Set<String> = emptySet()
)

class SettingsDataStore(private val context: Context) {

    private object Keys {
        val FAKE_DNS = booleanPreferencesKey("fake_dns_enabled")
        val LOCAL_DNS = booleanPreferencesKey("local_dns_enabled")
        val SNI_SNIFFING = booleanPreferencesKey("sni_sniffing_enabled")
        val LOCAL_SOCKS = booleanPreferencesKey("local_socks_enabled")
        val LOCAL_SOCKS_PORT = intPreferencesKey("local_socks_port")
        val PER_APP_ENABLED = booleanPreferencesKey("per_app_enabled")
        val PER_APP_BYPASS_MODE = booleanPreferencesKey("per_app_bypass_mode")
        val PER_APP_PACKAGES = stringSetPreferencesKey("per_app_packages")
    }

    val settingsFlow: Flow<TunnelSettings> = context.tunnelSettingsStore.data.map { prefs ->
        TunnelSettings(
            fakeDnsEnabled = prefs[Keys.FAKE_DNS] ?: true,
            localDnsEnabled = prefs[Keys.LOCAL_DNS] ?: true,
            sniSniffingEnabled = prefs[Keys.SNI_SNIFFING] ?: true,
            localSocksEnabled = prefs[Keys.LOCAL_SOCKS] ?: true,
            localSocksPort = prefs[Keys.LOCAL_SOCKS_PORT] ?: 10808,
            perAppEnabled = prefs[Keys.PER_APP_ENABLED] ?: false,
            perAppBypassMode = prefs[Keys.PER_APP_BYPASS_MODE] ?: true,
            perAppPackages = prefs[Keys.PER_APP_PACKAGES] ?: emptySet()
        )
    }

    suspend fun setFakeDnsEnabled(enabled: Boolean) {
        context.tunnelSettingsStore.edit { it[Keys.FAKE_DNS] = enabled }
    }

    suspend fun setLocalDnsEnabled(enabled: Boolean) {
        context.tunnelSettingsStore.edit { it[Keys.LOCAL_DNS] = enabled }
    }

    suspend fun setSniSniffingEnabled(enabled: Boolean) {
        context.tunnelSettingsStore.edit { it[Keys.SNI_SNIFFING] = enabled }
    }

    suspend fun setLocalSocksEnabled(enabled: Boolean) {
        context.tunnelSettingsStore.edit { it[Keys.LOCAL_SOCKS] = enabled }
    }

    suspend fun setPerAppEnabled(enabled: Boolean) {
        context.tunnelSettingsStore.edit { it[Keys.PER_APP_ENABLED] = enabled }
    }

    suspend fun setPerAppBypassMode(bypassMode: Boolean) {
        context.tunnelSettingsStore.edit { it[Keys.PER_APP_BYPASS_MODE] = bypassMode }
    }

    suspend fun setPerAppPackages(packages: Set<String>) {
        context.tunnelSettingsStore.edit { it[Keys.PER_APP_PACKAGES] = packages }
    }

    suspend fun togglePerAppPackage(packageName: String) {
        context.tunnelSettingsStore.edit { prefs ->
            val current = prefs[Keys.PER_APP_PACKAGES] ?: emptySet()
            prefs[Keys.PER_APP_PACKAGES] = if (current.contains(packageName)) {
                current - packageName
            } else {
                current + packageName
            }
        }
    }
}
