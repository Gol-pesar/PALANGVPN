package com.example.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.vpn.VpnConnectionState
import kotlinx.coroutines.delay
import java.util.Locale

@Composable
fun OrbitalConnectButton(
    connectionState: VpnConnectionState,
    connectedSinceMs: Long?,
    onToggleConnection: () -> Unit,
    modifier: Modifier = Modifier
) {
    val colorScheme = MaterialTheme.colorScheme
    val isConnected = connectionState is VpnConnectionState.Connected
    val isConnecting = connectionState is VpnConnectionState.Connecting
    val isError = connectionState is VpnConnectionState.Error

    val targetAccent = when (connectionState) {
        is VpnConnectionState.Connected -> colorScheme.primary
        is VpnConnectionState.Connecting -> colorScheme.tertiary
        is VpnConnectionState.Error -> colorScheme.error
        is VpnConnectionState.Disconnected -> colorScheme.secondary
    }

    val accentColor by animateColorAsState(
        targetValue = targetAccent,
        animationSpec = tween(durationMillis = 350),
        label = "accent_color"
    )

    val buttonScale by animateFloatAsState(
        targetValue = if (isConnected) 1.04f else 1.0f,
        animationSpec = spring(dampingRatio = 0.65f, stiffness = 320f),
        label = "button_scale"
    )

    val infiniteTransition = rememberInfiniteTransition(label = "orbital_rings")
    val orbitAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = if (isConnecting) 1600 else 6500,
                easing = LinearEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "orbit_angle"
    )

    val pulseProgress by infiniteTransition.animateFloat(
        initialValue = 0.88f,
        targetValue = 1.08f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_progress"
    )

    var elapsedSeconds by remember(connectedSinceMs) { mutableLongStateOf(0L) }
    LaunchedEffect(isConnected, connectedSinceMs) {
        if (isConnected && connectedSinceMs != null) {
            while (true) {
                elapsedSeconds = ((System.currentTimeMillis() - connectedSinceMs) / 1000L).coerceAtLeast(0L)
                delay(1000L)
            }
        } else {
            elapsedSeconds = 0L
        }
    }

    val statusText = when (connectionState) {
        is VpnConnectionState.Connected -> stringResource(R.string.status_connected)
        is VpnConnectionState.Connecting -> stringResource(R.string.status_connecting)
        is VpnConnectionState.Error -> stringResource(R.string.status_error)
        is VpnConnectionState.Disconnected -> stringResource(R.string.status_disconnected)
    }

    val actionDesc = if (isConnected || isConnecting) {
        stringResource(R.string.tap_to_disconnect)
    } else {
        stringResource(R.string.tap_to_connect)
    }

    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Box(
            modifier = Modifier.size(236.dp),
            contentAlignment = Alignment.Center
        ) {
            // Atmospheric radial glow + animated orbital rings
            Canvas(modifier = Modifier.size(236.dp)) {
                val center = Offset(size.width / 2f, size.height / 2f)
                val maxRadius = size.minDimension / 2f

                // Ambient halo
                val haloRadius = maxRadius * (if (isConnected || isConnecting) pulseProgress else 0.92f)
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(
                            accentColor.copy(alpha = if (isConnected) 0.24f else if (isConnecting) 0.20f else 0.11f),
                            accentColor.copy(alpha = 0.04f),
                            Color.Transparent
                        ),
                        center = center,
                        radius = haloRadius
                    ),
                    radius = haloRadius,
                    center = center
                )

                // Outer static track
                val outerRadius = maxRadius - 14.dp.toPx()
                drawCircle(
                    color = accentColor.copy(alpha = 0.16f),
                    radius = outerRadius,
                    center = center,
                    style = Stroke(width = 1.5.dp.toPx())
                )

                // Rotating orbital arc 1
                val arcSize = Size(outerRadius * 2f, outerRadius * 2f)
                val arcTopLeft = Offset(center.x - outerRadius, center.y - outerRadius)
                drawArc(
                    color = accentColor.copy(alpha = if (isConnected || isConnecting) 0.85f else 0.35f),
                    startAngle = orbitAngle,
                    sweepAngle = if (isConnecting) 115f else 75f,
                    useCenter = false,
                    topLeft = arcTopLeft,
                    size = arcSize,
                    style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
                )

                // Rotating orbital arc 2 (opposite)
                drawArc(
                    color = accentColor.copy(alpha = if (isConnected || isConnecting) 0.45f else 0.18f),
                    startAngle = orbitAngle + 180f,
                    sweepAngle = 45f,
                    useCenter = false,
                    topLeft = arcTopLeft,
                    size = arcSize,
                    style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
                )

                // Inner precision ring
                val innerRadius = outerRadius - 14.dp.toPx()
                drawCircle(
                    color = accentColor.copy(alpha = 0.12f),
                    radius = innerRadius,
                    center = center,
                    style = Stroke(width = 1.dp.toPx())
                )
            }

            // Interactive core power disc
            val interactionSource = remember { MutableInteractionSource() }
            Box(
                modifier = Modifier
                    .scale(buttonScale)
                    .size(152.dp)
                    .clip(CircleShape)
                    .background(
                        brush = Brush.verticalGradient(
                            colors = listOf(
                                colorScheme.surfaceContainerHigh,
                                colorScheme.surfaceContainerLow
                            )
                        )
                    )
                    .border(
                        width = 2.dp,
                        brush = Brush.linearGradient(
                            colors = listOf(
                                accentColor.copy(alpha = 0.9f),
                                accentColor.copy(alpha = 0.25f)
                            )
                        ),
                        shape = CircleShape
                    )
                    .clickable(
                        interactionSource = interactionSource,
                        indication = ripple(bounded = true, color = accentColor),
                        role = Role.Button,
                        onClick = onToggleConnection
                    )
                    .semantics { contentDescription = actionDesc }
                    .testTag("vpn_power_button"),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Icon(
                        imageVector = when {
                            isConnected -> Icons.Rounded.Shield
                            isError -> Icons.Rounded.WarningAmber
                            else -> Icons.Rounded.PowerSettingsNew
                        },
                        contentDescription = null,
                        tint = accentColor,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = if (isConnected) formatDuration(elapsedSeconds) else if (isConnecting) "SYNC" else "CONNECT",
                        style = MaterialTheme.typography.labelSmall.copy(
                            fontFamily = JetBrainsMonoFontFamily,
                            fontWeight = FontWeight.Bold
                        ),
                        color = accentColor
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = statusText,
            style = MaterialTheme.typography.headlineSmall,
            color = accentColor,
            modifier = Modifier.testTag("vpn_status_label")
        )

        Spacer(modifier = Modifier.height(4.dp))

        val subtitle = when (connectionState) {
            is VpnConnectionState.Connected -> "${connectionState.workerHost}  •  ${connectionState.cleanIp}"
            is VpnConnectionState.Connecting -> "تایید HMAC-SHA256 با ${connectionState.profileName}…"
            is VpnConnectionState.Error -> connectionState.message
            is VpnConnectionState.Disconnected -> actionDesc
        }

        Text(
            text = subtitle,
            style = if (isConnected) {
                MaterialTheme.typography.labelSmall.copy(fontFamily = JetBrainsMonoFontFamily)
            } else {
                MaterialTheme.typography.bodySmall
            },
            color = if (isError) colorScheme.error else colorScheme.onSurfaceVariant
        )
    }
}

private fun formatDuration(totalSeconds: Long): String {
    val hours = totalSeconds / 3600
    val minutes = (totalSeconds % 3600) / 60
    val seconds = totalSeconds % 60
    return String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
}
