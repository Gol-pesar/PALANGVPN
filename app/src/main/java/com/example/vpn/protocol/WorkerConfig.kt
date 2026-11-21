package com.example.vpn.protocol

import java.net.URI

data class ParsedWorkerEndpoint(
    val wsUrl: String,
    val workerHost: String,
    val port: Int,
    val path: String,
    val useTls: Boolean,
    val cleanIpHost: String?,
    val effectiveHostHeader: String
)

data class WorkerConfig(
    val profileId: Long = 0L,
    val profileName: String = "",
    val workerUrl: String,
    val uuid: String,
    val cleanIp: String = "",
    val sniSniffingEnabled: Boolean = true,
    val localSocksEnabled: Boolean = true,
    val localSocksPort: Int = 10808
) {
    fun validate(): String? {
        if (uuid.trim().isEmpty()) return "مقدار UUID نمی‌تواند خالی باشد"
        val parsed = parseEndpoint()
        if (parsed == null) return "فرمت Worker URL نامعتبر است"
        if (parsed.workerHost.isBlank() || !parsed.workerHost.contains(".")) {
            val isLocal = parsed.workerHost.equals("localhost", ignoreCase = true)
            if (!isLocal) return "دامنه Worker URL نامعتبر است"
        }
        return null
    }

    fun parseEndpoint(): ParsedWorkerEndpoint? {
        val raw = workerUrl.trim()
        if (raw.isEmpty()) return null

        val normalized = when {
            raw.startsWith("https://", ignoreCase = true) -> raw
            raw.startsWith("http://", ignoreCase = true) -> raw
            raw.startsWith("wss://", ignoreCase = true) -> "https://" + raw.substring(6)
            raw.startsWith("ws://", ignoreCase = true) -> "http://" + raw.substring(5)
            else -> "https://$raw"
        }

        val uri = runCatching { URI(normalized) }.getOrNull() ?: return null
        val host = uri.host?.trim().orEmpty()
        if (host.isEmpty()) return null

        val useTls = !uri.scheme.equals("http", ignoreCase = true)
        var port = if (uri.port > 0) uri.port else if (useTls) 443 else 80
        val rawPath = uri.rawPath.orEmpty().ifEmpty { "/" }
        val query = uri.rawQuery?.let { "?$it" }.orEmpty()
        val fullPath = "$rawPath$query"

        val (cleanHost, cleanPort) = parseCleanIp(cleanIp.trim())
        if (cleanPort != null) {
            port = cleanPort
        }

        val wsScheme = if (useTls) "wss" else "ws"
        val defaultPort = if (useTls) 443 else 80
        val portSegment = if (port == defaultPort) "" else ":$port"
        val wsUrl = "$wsScheme://$host$portSegment$fullPath"

        return ParsedWorkerEndpoint(
            wsUrl = wsUrl,
            workerHost = host,
            port = port,
            path = fullPath,
            useTls = useTls,
            cleanIpHost = cleanHost,
            effectiveHostHeader = host
        )
    }

    companion object {
        fun parseCleanIp(input: String): Pair<String?, Int?> {
            if (input.isBlank()) return null to null
            val cleaned = input.trim()
                .removePrefix("https://")
                .removePrefix("http://")
                .substringBefore("/")

            if (cleaned.startsWith("[")) {
                val closeIdx = cleaned.indexOf(']')
                if (closeIdx > 1) {
                    val ipv6 = cleaned.substring(1, closeIdx)
                    val after = cleaned.substring(closeIdx + 1)
                    val port = if (after.startsWith(":")) {
                        after.substring(1).toIntOrNull()?.takeIf { it in 1..65535 }
                    } else null
                    return ipv6 to port
                }
            }

            val colonCount = cleaned.count { it == ':' }
            if (colonCount == 1) {
                val hostPart = cleaned.substringBefore(':').trim()
                val portPart = cleaned.substringAfter(':').trim().toIntOrNull()
                    ?.takeIf { it in 1..65535 }
                if (hostPart.isNotEmpty() && portPart != null) {
                    return hostPart to portPart
                }
            }

            return cleaned.ifEmpty { null } to null
        }
    }
}
