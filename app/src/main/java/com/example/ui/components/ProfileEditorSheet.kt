package com.example.ui.components

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AutoFixHigh
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Label
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.data.ProfileRepository
import com.example.ui.ProfileEditorState
import com.example.ui.theme.JetBrainsMonoFontFamily

private val CLEAN_IP_PRESETS = listOf(
    "مستقیم (خالی)" to "",
    "104.16.132.229" to "104.16.132.229",
    "162.159.135.42" to "162.159.135.42",
    "104.17.70.206" to "104.17.70.206",
    "172.64.155.1" to "172.64.155.1"
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileEditorSheet(
    state: ProfileEditorState,
    onNameChange: (String) -> Unit,
    onWorkerUrlChange: (String) -> Unit,
    onUuidChange: (String) -> Unit,
    onCleanIpChange: (String) -> Unit,
    onGenerateUuid: () -> Unit,
    onSave: () -> Unit,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val colorScheme = MaterialTheme.colorScheme

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = colorScheme.surfaceContainer,
        contentColor = colorScheme.onSurface
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp)
                .padding(bottom = 24.dp)
                .navigationBarsPadding()
                .imePadding(),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text(
                text = if (state.editingId == 0L) "پروفایل جدید ورکر" else "ویرایش متغیرهای ورکر",
                style = MaterialTheme.typography.headlineSmall,
                color = colorScheme.onSurface
            )

            // Profile name
            OutlinedTextField(
                value = state.name,
                onValueChange = onNameChange,
                label = { Text(stringResource(R.string.label_profile_name)) },
                placeholder = { Text("مثلاً ورکر اصلی") },
                leadingIcon = { Icon(Icons.Rounded.Label, contentDescription = null) },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("editor_name_input")
            )

            // Worker URL (LTR monospace)
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                OutlinedTextField(
                    value = state.workerUrl,
                    onValueChange = onWorkerUrlChange,
                    label = { Text(stringResource(R.string.label_worker_url)) },
                    placeholder = {
                        Text(
                            text = stringResource(R.string.hint_worker_url),
                            fontFamily = JetBrainsMonoFontFamily
                        )
                    },
                    leadingIcon = { Icon(Icons.Rounded.Public, contentDescription = null) },
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFontFamily),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("editor_worker_url_input")
                )
            }

            // UUID (LTR monospace + generator)
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    OutlinedTextField(
                        value = state.uuid,
                        onValueChange = onUuidChange,
                        label = { Text(stringResource(R.string.label_uuid)) },
                        placeholder = {
                            Text(
                                text = stringResource(R.string.hint_uuid),
                                fontFamily = JetBrainsMonoFontFamily
                            )
                        },
                        leadingIcon = { Icon(Icons.Rounded.Key, contentDescription = null) },
                        trailingIcon = {
                            IconButton(
                                onClick = onGenerateUuid,
                                modifier = Modifier.testTag("editor_generate_uuid_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.AutoFixHigh,
                                    contentDescription = stringResource(R.string.action_generate_uuid),
                                    tint = colorScheme.primary
                                )
                            }
                        },
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFontFamily),
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("editor_uuid_input")
                    )
                }

                if (state.uuid.trim() != ProfileRepository.WORKER_DEFAULT_UUID) {
                    FilterChip(
                        selected = false,
                        onClick = { onUuidChange(ProfileRepository.WORKER_DEFAULT_UUID) },
                        label = {
                            Text(
                                text = "استفاده از UUID پیش‌فرض کد ورکر",
                                style = MaterialTheme.typography.labelMedium
                            )
                        },
                        modifier = Modifier.testTag("editor_default_uuid_chip")
                    )
                }
            }

            // Clean IP (LTR monospace + quick preset chips)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    OutlinedTextField(
                        value = state.cleanIp,
                        onValueChange = onCleanIpChange,
                        label = { Text(stringResource(R.string.label_clean_ip)) },
                        placeholder = {
                            Text(
                                text = "104.16.132.229 or 162.159.135.42:443",
                                fontFamily = JetBrainsMonoFontFamily
                            )
                        },
                        leadingIcon = { Icon(Icons.Rounded.Dns, contentDescription = null) },
                        supportingText = {
                            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                                Text(stringResource(R.string.helper_clean_ip))
                            }
                        },
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFontFamily),
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("editor_clean_ip_input")
                    )
                }

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CLEAN_IP_PRESETS.forEach { (label, ipValue) ->
                        FilterChip(
                            selected = state.cleanIp.trim() == ipValue,
                            onClick = { onCleanIpChange(ipValue) },
                            label = {
                                Text(
                                    text = label,
                                    style = if (ipValue.isNotEmpty()) {
                                        MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily)
                                    } else {
                                        MaterialTheme.typography.labelMedium
                                    }
                                )
                            }
                        )
                    }
                }
            }

            if (state.errorMessage != null) {
                Surface(
                    color = colorScheme.errorContainer,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = state.errorMessage,
                        style = MaterialTheme.typography.bodySmall,
                        color = colorScheme.onErrorContainer,
                        modifier = Modifier.padding(12.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(4.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedButton(
                    onClick = onDismiss,
                    modifier = Modifier
                        .weight(1f)
                        .height(50.dp)
                        .testTag("editor_cancel_button")
                ) {
                    Text(stringResource(R.string.action_cancel))
                }

                Button(
                    onClick = onSave,
                    modifier = Modifier
                        .weight(1.4f)
                        .height(50.dp)
                        .testTag("editor_save_button")
                ) {
                    Icon(
                        imageVector = Icons.Rounded.Save,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.action_save))
                }
            }
        }
    }
}
