package com.example.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

private val EdgeTunnelDarkColorScheme = darkColorScheme(
    primary = EmeraldGlow,
    onPrimary = EmeraldDeep,
    primaryContainer = EmeraldContainer,
    onPrimaryContainer = EmeraldOnContainer,
    secondary = CyanPulse,
    onSecondary = CyanDeep,
    secondaryContainer = CyanContainer,
    onSecondaryContainer = CyanOnContainer,
    tertiary = AmberConnecting,
    onTertiary = ObsidianBg,
    tertiaryContainer = AmberContainer,
    onTertiaryContainer = AmberOnContainer,
    error = CrimsonError,
    onError = ObsidianBg,
    errorContainer = CrimsonContainer,
    onErrorContainer = CrimsonOnContainer,
    background = ObsidianBg,
    onBackground = TextPrimary,
    surface = ObsidianSurface,
    onSurface = TextPrimary,
    surfaceVariant = ObsidianSurfaceContainerHigh,
    onSurfaceVariant = TextSecondary,
    surfaceContainerLowest = ObsidianBg,
    surfaceContainerLow = ObsidianSurfaceContainerLow,
    surfaceContainer = ObsidianSurfaceContainer,
    surfaceContainerHigh = ObsidianSurfaceContainerHigh,
    surfaceContainerHighest = ObsidianSurfaceContainerHighest,
    outline = OutlineStrong,
    outlineVariant = OutlineSubtle
)

val EdgeTunnelShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(32.dp)
)

@Composable
fun EdgeTunnelTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = EdgeTunnelDarkColorScheme,
        typography = AppTypography,
        shapes = EdgeTunnelShapes,
        content = content
    )
}
