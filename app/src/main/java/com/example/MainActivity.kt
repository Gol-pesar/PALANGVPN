package com.example

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Terminal
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.MainViewModel
import com.example.ui.components.ProfileEditorSheet
import com.example.ui.screens.ConnectScreen
import com.example.ui.screens.LogsToolsScreen
import com.example.ui.screens.ProfilesScreen
import com.example.ui.theme.EdgeTunnelTheme
import com.example.vpn.VpnConnectionState
import com.example.vpn.WorkerVpnService
import com.example.vpn.protocol.WorkerConfig

private enum class AppTab(
    val routeId: String,
    val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
) {
    CONNECT("connect", R.string.nav_connect, Icons.Rounded.Shield, Icons.Outlined.Shield),
    PROFILES("profiles", R.string.nav_profiles, Icons.Rounded.Dns, Icons.Outlined.Dns),
    LOGS("logs", R.string.nav_logs, Icons.Rounded.Terminal, Icons.Outlined.Terminal)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)
        )
        setContent {
            EdgeTunnelTheme {
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                    EdgeTunnelApp()
                }
            }
        }
    }
}

@Composable
private fun EdgeTunnelApp(
    viewModel: MainViewModel = viewModel()
) {
    val context = LocalContext.current
    val profiles by viewModel.profiles.collectAsStateWithLifecycle()
    val selectedProfile by viewModel.selectedProfile.collectAsStateWithLifecycle()
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val connectionState by viewModel.connectionState.collectAsStateWithLifecycle()
    val trafficStats by viewModel.trafficStats.collectAsStateWithLifecycle()
    val logs by viewModel.logs.collectAsStateWithLifecycle()
    val testingProfileIds by viewModel.testingProfileIds.collectAsStateWithLifecycle()
    val editorState by viewModel.editorState.collectAsStateWithLifecycle()

    var currentTab by rememberSaveable { mutableStateOf(AppTab.CONNECT) }
    var pendingConfigToStart by remember { mutableStateOf<WorkerConfig?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    fun startVpnServiceNow(config: WorkerConfig) {
        val intent = WorkerVpnService.createConnectIntent(context, config)
        ContextCompat.startForegroundService(context, intent)
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val config = pendingConfigToStart
        pendingConfigToStart = null
        if (result.resultCode == Activity.RESULT_OK && config != null) {
            startVpnServiceNow(config)
        } else if (result.resultCode != Activity.RESULT_OK) {
            viewModel.emitMessage(context.getString(R.string.error_vpn_permission_denied))
        }
    }

    fun proceedWithVpnConsent(config: WorkerConfig) {
        val prepareIntent: Intent? = VpnService.prepare(context)
        if (prepareIntent != null) {
            pendingConfigToStart = config
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnServiceNow(config)
        }
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { _ ->
        val config = pendingConfigToStart
        if (config != null) {
            proceedWithVpnConsent(config)
        }
    }

    fun handleToggleVpn() {
        val isActive = connectionState is VpnConnectionState.Connected ||
            connectionState is VpnConnectionState.Connecting
        if (isActive) {
            context.startService(WorkerVpnService.createDisconnectIntent(context))
            return
        }

        val (config, error) = viewModel.buildActiveWorkerConfig()
        if (error != null || config == null) {
            viewModel.emitMessage(error ?: "لطفاً متغیرهای ورکر را تکمیل کنید")
            selectedProfile?.let { viewModel.openEditProfileEditor(it) }
                ?: viewModel.openCreateProfileEditor()
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                pendingConfigToStart = config
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                return
            }
        }
        proceedWithVpnConsent(config)
    }

    // Handle system back button cleanly from non-home tabs
    BackHandler(enabled = currentTab != AppTab.CONNECT) {
        currentTab = AppTab.CONNECT
    }

    BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
        val useNavigationRail = maxWidth >= 600.dp

        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = MaterialTheme.colorScheme.background,
            contentWindowInsets = WindowInsets.safeDrawing,
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
            bottomBar = {
                if (!useNavigationRail) {
                    NavigationBar(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                        windowInsets = WindowInsets.navigationBars
                    ) {
                        AppTab.entries.forEach { tab ->
                            val selected = currentTab == tab
                            NavigationBarItem(
                                selected = selected,
                                onClick = { currentTab = tab },
                                icon = {
                                    Icon(
                                        imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                        contentDescription = stringResource(tab.labelRes)
                                    )
                                },
                                label = { Text(stringResource(tab.labelRes)) },
                                modifier = Modifier.testTag("nav_tab_${tab.routeId}")
                            )
                        }
                    }
                }
            }
        ) { innerPadding ->
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                if (useNavigationRail) {
                    NavigationRail(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerLow
                    ) {
                        AppTab.entries.forEach { tab ->
                            val selected = currentTab == tab
                            NavigationRailItem(
                                selected = selected,
                                onClick = { currentTab = tab },
                                icon = {
                                    Icon(
                                        imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                                        contentDescription = stringResource(tab.labelRes)
                                    )
                                },
                                label = { Text(stringResource(tab.labelRes)) },
                                modifier = Modifier.testTag("nav_rail_${tab.routeId}")
                            )
                        }
                    }
                }

                Box(modifier = Modifier.weight(1f)) {
                    when (currentTab) {
                        AppTab.CONNECT -> ConnectScreen(
                            selectedProfile = selectedProfile,
                            connectionState = connectionState,
                            trafficStats = trafficStats,
                            isTestingPing = selectedProfile?.let { testingProfileIds.contains(it.id) } == true,
                            onToggleConnection = ::handleToggleVpn,
                            onTestPing = { selectedProfile?.let(viewModel::testProfileHandshake) },
                            onEditProfile = viewModel::openEditProfileEditor,
                            onCreateProfile = viewModel::openCreateProfileEditor
                        )

                        AppTab.PROFILES -> ProfilesScreen(
                            profiles = profiles,
                            testingProfileIds = testingProfileIds,
                            onSelectProfile = viewModel::selectProfile,
                            onCreateProfile = viewModel::openCreateProfileEditor,
                            onEditProfile = viewModel::openEditProfileEditor,
                            onDeleteProfile = viewModel::deleteProfile,
                            onTestProfile = viewModel::testProfileHandshake,
                            onExportUri = viewModel::exportProfileUri,
                            onImportClipboard = viewModel::importProfileFromClipboard,
                            onCopiedFeedback = viewModel::emitMessage
                        )

                        AppTab.LOGS -> LogsToolsScreen(
                            settings = settings,
                            logs = logs,
                            onSniSniffingChanged = viewModel::setSniSniffingEnabled,
                            onLocalSocksChanged = viewModel::setLocalSocksEnabled,
                            onClearLogs = viewModel::clearLogs,
                            onCopiedFeedback = viewModel::emitMessage
                        )
                    }
                }
            }
        }
    }

    if (editorState.isOpen) {
        ProfileEditorSheet(
            state = editorState,
            onNameChange = viewModel::updateEditorName,
            onWorkerUrlChange = viewModel::updateEditorWorkerUrl,
            onUuidChange = viewModel::updateEditorUuid,
            onCleanIpChange = viewModel::updateEditorCleanIp,
            onGenerateUuid = viewModel::generateRandomUuidInEditor,
            onSave = viewModel::saveEditorProfile,
            onDismiss = viewModel::closeEditor
        )
    }
}
