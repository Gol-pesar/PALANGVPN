package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Hub
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.data.ServerProfileEntity
import com.example.ui.components.OrbitalConnectButton
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.vpn.VpnConnectionState
import com.example.vpn.VpnTrafficStats
import java.util.Locale

@Composable
fun ConnectScreen(
    selectedProfile: ServerProfileEntity?,
    connectionState: VpnConnectionState,
    trafficStats: VpnTrafficStats,
    isTestingPing: Boolean,
    onToggleConnection: () -> Unit,
    onTestPing: () -> Unit,
    onEditProfile: (ServerProfileEntity) -> Unit,
    onCreateProfile: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colorScheme = MaterialTheme.colorScheme
    var revealUuid by remember { mutableStateOf(false) }

    Box(
        modifier = modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        colorScheme.surfaceContainerLow.copy(alpha = 0.7f),
                        colorScheme.background,
                        colorScheme.background
                    )
                )
            ),
        contentAlignment = Alignment.TopCenter
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .widthIn(max = 640.dp)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            // Top bar: Brand + Latency Test Pill
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = stringResource(R.string.app_name),
                        style = MaterialTheme.typography.headlineSmall,
                        color = colorScheme.onBackground
                    )
                    Text(
                        text = stringResource(R.string.app_subtitle),
                        style = MaterialTheme.typography.bodySmall,
                        color = colorScheme.onSurfaceVariant
                    )
                }

                Surface(
                    shape = MaterialTheme.shapes.large,
                    color = colorScheme.surfaceContainerHigh,
                    border = BorderStroke(1.dp, colorScheme.outlineVariant),
                    modifier = Modifier
                        .clip(MaterialTheme.shapes.large)
                        .clickable(enabled = selectedProfile != null && !isTestingPing, onClick = onTestPing)
                        .testTag("dashboard_ping_chip")
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (isTestingPing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = colorScheme.primary
                            )
                        } else {
                            Icon(
                                imageVector = Icons.Rounded.Speed,
                                contentDescription = stringResource(R.string.action_test_ping),
                                tint = colorScheme.primary,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        val pingText = when {
                            isTestingPing -> stringResource(R.string.action_testing)
                            selectedProfile?.lastLatencyMs != null -> "${selectedProfile.lastLatencyMs} ms"
                            else -> stringResource(R.string.action_test_ping)
                        }
                        Text(
                            text = pingText,
                            style = MaterialTheme.typography.labelMedium.copy(
                                fontFamily = if (selectedProfile?.lastLatencyMs != null && !isTestingPing) {
                                    JetBrainsMonoFontFamily
                                } else {
                                    MaterialTheme.typography.labelMedium.fontFamily
                                }
                            ),
                            color = colorScheme.onSurface
                        )
                    }
                }
            }

            // Centerpiece Orbital Power Button
            OrbitalConnectButton(
                connectionState = connectionState,
                connectedSinceMs = trafficStats.connectedSinceMs,
                onToggleConnection = onToggleConnection,
                modifier = Modifier.padding(vertical = 4.dp)
            )

            // Live Telemetry Strip
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                TelemetryCard(
                    label = stringResource(R.string.metric_download),
                    primaryValue = formatSpeed(trafficStats.downloadSpeedBps),
                    secondaryValue = formatBytes(trafficStats.downloadBytes),
                    icon = Icons.Rounded.ArrowDownward,
                    accent = colorScheme.primary,
                    modifier = Modifier.weight(1f)
                )
                TelemetryCard(
                    label = stringResource(R.string.metric_upload),
                    primaryValue = formatSpeed(trafficStats.uploadSpeedBps),
                    secondaryValue = formatBytes(trafficStats.uploadBytes),
                    icon = Icons.Rounded.ArrowUpward,
                    accent = colorScheme.secondary,
                    modifier = Modifier.weight(1f)
                )
                TelemetryCard(
                    label = stringResource(R.string.metric_tunnels),
                    primaryValue = trafficStats.activeTunnels.toString(),
                    secondaryValue = "TCP",
                    icon = Icons.Rounded.Hub,
                    accent = colorScheme.tertiary,
                    modifier = Modifier.weight(0.85f)
                )
            }

            // Local SOCKS5 active indicator pill
            AnimatedVisibility(visible = trafficStats.socksProxyAddress != null) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = colorScheme.primaryContainer.copy(alpha = 0.55f),
                    border = BorderStroke(1.dp, colorScheme.primary.copy(alpha = 0.35f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "پروکسی محلی SOCKS5 آماده است",
                            style = MaterialTheme.typography.labelMedium,
                            color = colorScheme.onPrimaryContainer
                        )
                        Text(
                            text = trafficStats.socksProxyAddress.orEmpty(),
                            style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily),
                            color = colorScheme.primary
                        )
                    }
                }
            }

            // Active Worker Variables Card (Worker URL, UUID, Clean IP)
            Card(
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(containerColor = colorScheme.surfaceContainer),
                border = BorderStroke(1.dp, colorScheme.outlineVariant),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("active_worker_config_card")
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(36.dp)
                                    .clip(CircleShape)
                                    .background(colorScheme.primaryContainer),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.Tune,
                                    contentDescription = null,
                                    tint = colorScheme.primary,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                            Column {
                                Text(
                                    text = selectedProfile?.name ?: stringResource(R.string.section_active_config),
                                    style = MaterialTheme.typography.titleMedium,
                                    color = colorScheme.onSurface
                                )
                                Text(
                                    text = stringResource(R.string.protocol_spec_value),
                                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily),
                                    color = colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        FilledTonalButton(
                            onClick = {
                                if (selectedProfile != null) {
                                    onEditProfile(selectedProfile)
                                } else {
                                    onCreateProfile()
                                }
                            },
                            modifier = Modifier.testTag("edit_active_config_button")
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Edit,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = stringResource(R.string.action_edit_config),
                                style = MaterialTheme.typography.labelMedium
                            )
                        }
                    }

                    HorizontalDivider(color = colorScheme.outlineVariant.copy(alpha = 0.6f))

                    // Variable 1: Worker URL
                    ConfigVariableRow(
                        icon = Icons.Rounded.Public,
                        label = stringResource(R.string.label_worker_url),
                        value = selectedProfile?.workerUrl?.ifBlank { "تنظیم نشده — برای ورود لمس کنید" }
                            ?: "تنظیم نشده",
                        isMissing = selectedProfile?.workerUrl.isNullOrBlank(),
                        onClick = {
                            selectedProfile?.let(onEditProfile) ?: onCreateProfile()
                        }
                    )

                    // Variable 2: UUID
                    ConfigVariableRow(
                        icon = Icons.Rounded.Key,
                        label = stringResource(R.string.label_uuid),
                        value = selectedProfile?.uuid?.let { raw ->
                            if (raw.isBlank()) "تنظیم نشده"
                            else if (revealUuid) raw
                            else maskUuid(raw)
                        } ?: "تنظیم نشده",
                        isMissing = selectedProfile?.uuid.isNullOrBlank(),
                        trailingContent = {
                            IconButton(
                                onClick = { revealUuid = !revealUuid },
                                modifier = Modifier.testTag("toggle_uuid_visibility_button")
                            ) {
                                Icon(
                                    imageVector = if (revealUuid) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility,
                                    contentDescription = if (revealUuid) "مخفی کردن UUID" else "نمایش UUID",
                                    tint = colorScheme.onSurfaceVariant,
                                    modifier = Modifier.size(20.dp)
                                )
                            }
                        },
                        onClick = {
                            selectedProfile?.let(onEditProfile) ?: onCreateProfile()
                        }
                    )

                    // Variable 3: Clean IP
                    ConfigVariableRow(
                        icon = Icons.Rounded.Dns,
                        label = stringResource(R.string.label_clean_ip),
                        value = selectedProfile?.cleanIp?.ifBlank { "مستقیم (DNS دامنه ورکر)" }
                            ?: "مستقیم",
                        isMissing = false,
                        onClick = {
                            selectedProfile?.let(onEditProfile) ?: onCreateProfile()
                        }
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@Composable
private fun TelemetryCard(
    label: String,
    primaryValue: String,
    secondaryValue: String,
    icon: ImageVector,
    accent: Color,
    modifier: Modifier = Modifier
) {
    val colorScheme = MaterialTheme.colorScheme
    Card(
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(containerColor = colorScheme.surfaceContainer),
        border = BorderStroke(1.dp, colorScheme.outlineVariant),
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(16.dp)
                )
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelMedium,
                    color = colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                Text(
                    text = primaryValue,
                    style = MaterialTheme.typography.titleSmall.copy(
                        fontFamily = JetBrainsMonoFontFamily,
                        fontWeight = FontWeight.Bold
                    ),
                    color = colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = secondaryValue,
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily),
                    color = colorScheme.onSurfaceVariant,
                    maxLines = 1
                )
            }
        }
    }
}

@Composable
private fun ConfigVariableRow(
    icon: ImageVector,
    label: String,
    value: String,
    isMissing: Boolean,
    trailingContent: (@Composable () -> Unit)? = null,
    onClick: () -> Unit
) {
    val colorScheme = MaterialTheme.colorScheme
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.small)
            .clickable(onClick = onClick)
            .padding(vertical = 6.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (isMissing) colorScheme.tertiary else colorScheme.secondary,
            modifier = Modifier.size(20.dp)
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = colorScheme.onSurfaceVariant
            )
            CompositionLocalProvider(
                LocalLayoutDirection provides if (isMissing) LayoutDirection.Rtl else LayoutDirection.Ltr
            ) {
                Text(
                    text = value,
                    style = if (isMissing) {
                        MaterialTheme.typography.bodySmall
                    } else {
                        MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFontFamily)
                    },
                    color = if (isMissing) colorScheme.tertiary else colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        trailingContent?.invoke()
    }
}

private fun maskUuid(uuid: String): String {
    if (uuid.length <= 12) return "••••••••"
    return "${uuid.take(8)}••••-••••-${uuid.takeLast(4)}"
}

private fun formatSpeed(bytesPerSec: Long): String {
    return when {
        bytesPerSec >= 1_048_576L -> String.format(Locale.US, "%.1f MB/s", bytesPerSec / 1_048_576.0)
        bytesPerSec >= 1_024L -> String.format(Locale.US, "%.1f KB/s", bytesPerSec / 1_024.0)
        else -> "$bytesPerSec B/s"
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1_073_741_824L -> String.format(Locale.US, "%.2f GB", bytes / 1_073_741_824.0)
        bytes >= 1_048_576L -> String.format(Locale.US, "%.1f MB", bytes / 1_048_576.0)
        bytes >= 1_024L -> String.format(Locale.US, "%.1f KB", bytes / 1_024.0)
        else -> "$bytes B"
    }
}
