package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.ContentPasteGo
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.RadioButtonUnchecked
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.data.ServerProfileEntity
import com.example.ui.theme.JetBrainsMonoFontFamily

@Composable
fun ProfilesScreen(
    profiles: List<ServerProfileEntity>,
    testingProfileIds: Set<Long>,
    onSelectProfile: (Long) -> Unit,
    onCreateProfile: () -> Unit,
    onEditProfile: (ServerProfileEntity) -> Unit,
    onDeleteProfile: (ServerProfileEntity) -> Unit,
    onTestProfile: (ServerProfileEntity) -> Unit,
    onExportUri: (ServerProfileEntity) -> String,
    onImportClipboard: (String) -> Unit,
    onCopiedFeedback: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val colorScheme = MaterialTheme.colorScheme
    val clipboard = LocalClipboardManager.current

    Box(
        modifier = modifier.fillMaxSize(),
        contentAlignment = Alignment.TopCenter
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .widthIn(max = 640.dp)
                .padding(horizontal = 20.dp)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp, bottom = 12.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = stringResource(R.string.nav_profiles),
                        style = MaterialTheme.typography.headlineSmall,
                        color = colorScheme.onBackground
                    )
                    Text(
                        text = "${profiles.size} پیکربندی ذخیره شده",
                        style = MaterialTheme.typography.bodySmall,
                        color = colorScheme.onSurfaceVariant
                    )
                }

                OutlinedButton(
                    onClick = {
                        val clip = clipboard.getText()?.text.orEmpty()
                        onImportClipboard(clip)
                    },
                    modifier = Modifier.testTag("import_clipboard_button")
                ) {
                    Icon(
                        imageVector = Icons.Rounded.ContentPasteGo,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = "وارد کردن لینک",
                        style = MaterialTheme.typography.labelMedium
                    )
                }
            }

            if (profiles.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .weight(1f),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.VpnKey,
                            contentDescription = null,
                            tint = colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(48.dp)
                        )
                        Text(
                            text = stringResource(R.string.profiles_empty_hint),
                            style = MaterialTheme.typography.bodyMedium,
                            color = colorScheme.onSurfaceVariant
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(bottom = 88.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(profiles, key = { it.id }) { profile ->
                        ProfileItemCard(
                            profile = profile,
                            isTesting = testingProfileIds.contains(profile.id),
                            canDelete = profiles.size > 1,
                            onSelect = { onSelectProfile(profile.id) },
                            onEdit = { onEditProfile(profile) },
                            onDelete = { onDeleteProfile(profile) },
                            onTest = { onTestProfile(profile) },
                            onCopy = {
                                val uri = onExportUri(profile)
                                clipboard.setText(AnnotatedString(uri))
                                onCopiedFeedback("لینک کانفیگ در کلیپ‌بورد کپی شد")
                            }
                        )
                    }
                }
            }
        }

        FloatingActionButton(
            onClick = onCreateProfile,
            containerColor = colorScheme.primary,
            contentColor = colorScheme.onPrimary,
            modifier = Modifier
                .align(Alignment.BottomStart)
                .padding(20.dp)
                .testTag("add_profile_fab")
        ) {
            Icon(
                imageVector = Icons.Rounded.Add,
                contentDescription = stringResource(R.string.action_add_profile)
            )
        }
    }
}

@Composable
private fun ProfileItemCard(
    profile: ServerProfileEntity,
    isTesting: Boolean,
    canDelete: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onTest: () -> Unit,
    onCopy: () -> Unit
) {
    val colorScheme = MaterialTheme.colorScheme
    val borderColor = if (profile.isSelected) colorScheme.primary else colorScheme.outlineVariant

    Card(
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = if (profile.isSelected) {
                colorScheme.surfaceContainerHigh
            } else {
                colorScheme.surfaceContainer
            }
        ),
        border = BorderStroke(if (profile.isSelected) 1.5.dp else 1.dp, borderColor),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onSelect)
            .testTag("profile_card_${profile.id}")
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(
                        imageVector = if (profile.isSelected) {
                            Icons.Rounded.CheckCircle
                        } else {
                            Icons.Rounded.RadioButtonUnchecked
                        },
                        contentDescription = null,
                        tint = if (profile.isSelected) colorScheme.primary else colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(22.dp)
                    )
                    Text(
                        text = profile.name,
                        style = MaterialTheme.typography.titleMedium,
                        color = colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                // Latency badge
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = when {
                        profile.lastLatencyMs == null -> colorScheme.surfaceContainerLowest
                        profile.lastLatencyMs < 350 -> colorScheme.primaryContainer
                        else -> colorScheme.tertiaryContainer
                    }
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        if (isTesting) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(12.dp),
                                strokeWidth = 1.8.dp,
                                color = colorScheme.primary
                            )
                        }
                        Text(
                            text = when {
                                isTesting -> "…"
                                profile.lastLatencyMs != null -> "${profile.lastLatencyMs} ms"
                                else -> "تست نشده"
                            },
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontFamily = if (profile.lastLatencyMs != null) JetBrainsMonoFontFamily else MaterialTheme.typography.labelSmall.fontFamily
                            ),
                            color = when {
                                profile.lastLatencyMs == null -> colorScheme.onSurfaceVariant
                                profile.lastLatencyMs < 350 -> colorScheme.onPrimaryContainer
                                else -> colorScheme.onTertiaryContainer
                            }
                        )
                    }
                }
            }

            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "URL: ${profile.workerUrl.ifBlank { "(empty)" }}",
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = JetBrainsMonoFontFamily),
                        color = if (profile.workerUrl.isBlank()) colorScheme.tertiary else colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "Clean IP: ${profile.cleanIp.ifBlank { "Direct DNS" }}  •  UUID: ${profile.uuid.take(8)}…",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily),
                        color = colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            HorizontalDivider(color = colorScheme.outlineVariant.copy(alpha = 0.5f))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    IconButton(
                        onClick = onTest,
                        enabled = !isTesting,
                        modifier = Modifier.testTag("profile_test_${profile.id}")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Speed,
                            contentDescription = stringResource(R.string.action_test_ping),
                            tint = colorScheme.primary
                        )
                    }
                    IconButton(
                        onClick = onEdit,
                        modifier = Modifier.testTag("profile_edit_${profile.id}")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Edit,
                            contentDescription = stringResource(R.string.action_edit_config),
                            tint = colorScheme.secondary
                        )
                    }
                    IconButton(
                        onClick = onCopy,
                        modifier = Modifier.testTag("profile_copy_${profile.id}")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.ContentCopy,
                            contentDescription = stringResource(R.string.action_copy_config),
                            tint = colorScheme.onSurfaceVariant
                        )
                    }
                }

                if (canDelete) {
                    IconButton(
                        onClick = onDelete,
                        modifier = Modifier.testTag("profile_delete_${profile.id}")
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.DeleteOutline,
                            contentDescription = stringResource(R.string.action_delete),
                            tint = colorScheme.error
                        )
                    }
                }
            }
        }
    }
}
