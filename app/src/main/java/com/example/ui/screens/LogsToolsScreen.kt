package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.DeleteSweep
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.data.TunnelSettings
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.vpn.LogLevel
import com.example.vpn.VpnLogEntry

@Composable
fun LogsToolsScreen(
    settings: TunnelSettings,
    logs: List<VpnLogEntry>,
    onFakeDnsChanged: (Boolean) -> Unit,
    onLocalDnsChanged: (Boolean) -> Unit,
    onPerAppEnabledChanged: (Boolean) -> Unit,
    onOpenPerAppPicker: () -> Unit,
    onSniSniffingChanged: (Boolean) -> Unit,
    onLocalSocksChanged: (Boolean) -> Unit,
    onClearLogs: () -> Unit,
    onCopiedFeedback: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val colorScheme = MaterialTheme.colorScheme
    val clipboard = LocalClipboardManager.current
    val listState = rememberLazyListState()

    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.lastIndex)
        }
    }

    Box(
        modifier = modifier.fillMaxSize(),
        contentAlignment = Alignment.TopCenter
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .widthIn(max = 640.dp)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text(
                text = stringResource(R.string.nav_logs),
                style = MaterialTheme.typography.headlineSmall,
                color = colorScheme.onBackground
            )

            // Tunnel Core & DNS Settings Card
            Card(
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(containerColor = colorScheme.surfaceContainer),
                border = BorderStroke(1.dp, colorScheme.outlineVariant),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Security,
                            contentDescription = null,
                            tint = colorScheme.primary,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = stringResource(R.string.section_tunnel_options),
                            style = MaterialTheme.typography.titleMedium,
                            color = colorScheme.onSurface
                        )
                    }

                    // Enable Fake DNS
                    SettingToggleRow(
                        title = stringResource(R.string.option_fake_dns),
                        subtitle = stringResource(R.string.option_fake_dns_desc),
                        checked = settings.fakeDnsEnabled,
                        onCheckedChange = onFakeDnsChanged,
                        tag = "toggle_fake_dns"
                    )

                    HorizontalDivider(color = colorScheme.outlineVariant.copy(alpha = 0.5f))

                    // Enable Local DNS
                    SettingToggleRow(
                        title = stringResource(R.string.option_local_dns),
                        subtitle = stringResource(R.string.option_local_dns_desc),
                        checked = settings.localDnsEnabled,
                        onCheckedChange = onLocalDnsChanged,
                        tag = "toggle_local_dns"
                    )

                    HorizontalDivider(color = colorScheme.outlineVariant.copy(alpha = 0.5f))

                    // Per-App Proxy + Picker Button
                    SettingToggleRow(
                        title = stringResource(R.string.option_per_app_proxy),
                        subtitle = if (settings.perAppEnabled) {
                            val modeLabel = if (settings.perAppBypassMode) {
                                stringResource(R.string.per_app_mode_bypass)
                            } else {
                                stringResource(R.string.per_app_mode_proxy_only)
                            }
                            "$modeLabel • ${settings.perAppPackages.size} برنامه انتخاب شده"
                        } else {
                            stringResource(R.string.option_per_app_proxy_desc)
                        },
                        checked = settings.perAppEnabled,
                        onCheckedChange = onPerAppEnabledChanged,
                        tag = "toggle_per_app_proxy"
                    )

                    AnimatedVisibility(visible = settings.perAppEnabled) {
                        FilledTonalButton(
                            onClick = onOpenPerAppPicker,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("open_per_app_picker_button")
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Apps,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "${stringResource(R.string.action_select_apps)} (${settings.perAppPackages.size})",
                                style = MaterialTheme.typography.labelLarge
                            )
                        }
                    }

                    // Self-Bypass permanent badge
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = colorScheme.primaryContainer.copy(alpha = 0.35f),
                        border = BorderStroke(1.dp, colorScheme.primary.copy(alpha = 0.25f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.VerifiedUser,
                                contentDescription = null,
                                tint = colorScheme.primary,
                                modifier = Modifier.size(16.dp)
                            )
                            Text(
                                text = stringResource(R.string.self_bypass_notice),
                                style = MaterialTheme.typography.bodySmall,
                                color = colorScheme.onPrimaryContainer
                            )
                        }
                    }

                    HorizontalDivider(color = colorScheme.outlineVariant.copy(alpha = 0.5f))

                    SettingToggleRow(
                        title = stringResource(R.string.option_sni_sniffing),
                        subtitle = stringResource(R.string.option_sni_sniffing_desc),
                        checked = settings.sniSniffingEnabled,
                        onCheckedChange = onSniSniffingChanged,
                        tag = "toggle_sni_sniffing"
                    )

                    HorizontalDivider(color = colorScheme.outlineVariant.copy(alpha = 0.5f))

                    SettingToggleRow(
                        title = stringResource(R.string.option_local_socks),
                        subtitle = stringResource(R.string.option_local_socks_desc),
                        checked = settings.localSocksEnabled,
                        onCheckedChange = onLocalSocksChanged,
                        tag = "toggle_local_socks"
                    )

                    HorizontalDivider(color = colorScheme.outlineVariant.copy(alpha = 0.5f))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.protocol_spec_title),
                            style = MaterialTheme.typography.labelMedium,
                            color = colorScheme.onSurfaceVariant
                        )
                        CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                            Text(
                                text = stringResource(R.string.protocol_spec_value),
                                style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily),
                                color = colorScheme.secondary
                            )
                        }
                    }
                }
            }

            // Diagnostic Log Console Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Terminal,
                        contentDescription = null,
                        tint = colorScheme.secondary,
                        modifier = Modifier.size(20.dp)
                    )
                    Text(
                        text = "کنسول عیب‌یابی زنده",
                        style = MaterialTheme.typography.titleMedium,
                        color = colorScheme.onBackground
                    )
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = {
                            val dump = logs.joinToString("\n") { "[${it.timestamp}] ${it.level.name}: ${it.message}" }
                            clipboard.setText(AnnotatedString(dump))
                            onCopiedFeedback("گزارش‌ها در کلیپ‌بورد کپی شدند")
                        },
                        enabled = logs.isNotEmpty(),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        modifier = Modifier.testTag("copy_logs_button")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.ContentCopy,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = stringResource(R.string.action_copy_logs),
                            style = MaterialTheme.typography.labelMedium
                        )
                    }

                    OutlinedButton(
                        onClick = onClearLogs,
                        enabled = logs.isNotEmpty(),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp),
                        modifier = Modifier.testTag("clear_logs_button")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.DeleteSweep,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp)
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = stringResource(R.string.action_clear_logs),
                            style = MaterialTheme.typography.labelMedium
                        )
                    }
                }
            }

            // Terminal Container
            Card(
                shape = MaterialTheme.shapes.large,
                colors = CardDefaults.cardColors(containerColor = colorScheme.surfaceContainerLowest),
                border = BorderStroke(1.dp, colorScheme.outlineVariant),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(260.dp)
            ) {
                if (logs.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(24.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = stringResource(R.string.logs_empty_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = colorScheme.onSurfaceVariant
                        )
                    }
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(14.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(logs, key = { it.id }) { entry ->
                            val badgeColor = when (entry.level) {
                                LogLevel.SUCCESS -> colorScheme.primary
                                LogLevel.INFO -> colorScheme.secondary
                                LogLevel.WARN -> colorScheme.tertiary
                                LogLevel.ERROR -> colorScheme.error
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.Top
                            ) {
                                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                                    Text(
                                        text = entry.timestamp,
                                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily),
                                        color = colorScheme.onSurfaceVariant
                                    )
                                }
                                Text(
                                    text = entry.message,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = badgeColor,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
        }
    }
}

@Composable
private fun SettingToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    tag: String
) {
    val colorScheme = MaterialTheme.colorScheme
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .padding(end = 12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = colorScheme.onSurface
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = colorScheme.onSurfaceVariant
            )
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            modifier = Modifier.testTag(tag)
        )
    }
}
