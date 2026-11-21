package com.example.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.tunnelSettingsStore: DataStore<Preferences> by preferencesDataStore(
    name = "edgetunnel_settings"
)

data class TunnelSettings(
    val sniSniffingEnabled: Boolean = true,
    val localSocksEnabled: Boolean = true,
    val localSocksPort: Int = 10808
)

class SettingsDataStore(private val context: Context) {

    private object Keys {
        val SNI_SNIFFING = booleanPreferencesKey("sni_sniffing_enabled")
        val LOCAL_SOCKS = booleanPreferencesKey("local_socks_enabled")
        val LOCAL_SOCKS_PORT = intPreferencesKey("local_socks_port")
    }

    val settingsFlow: Flow<TunnelSettings> = context.tunnelSettingsStore.data.map { prefs ->
        TunnelSettings(
            sniSniffingEnabled = prefs[Keys.SNI_SNIFFING] ?: true,
            localSocksEnabled = prefs[Keys.LOCAL_SOCKS] ?: true,
            localSocksPort = prefs[Keys.LOCAL_SOCKS_PORT] ?: 10808
        )
    }

    suspend fun setSniSniffingEnabled(enabled: Boolean) {
        context.tunnelSettingsStore.edit { it[Keys.SNI_SNIFFING] = enabled }
    }

    suspend fun setLocalSocksEnabled(enabled: Boolean) {
        context.tunnelSettingsStore.edit { it[Keys.LOCAL_SOCKS] = enabled }
    }
}
