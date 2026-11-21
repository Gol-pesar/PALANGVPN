package com.example.vpn.protocol

import java.io.ByteArrayOutputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Exact binary protocol & cryptographic primitives matching worker_534a9c26.js:
 * - WebSocket subprotocol: "chat.v2"
 * - Init frame: [16-byte nonce] + XOR(body, key) + [8-byte trailer]
 *   where key[i] = utf8(uuid)[i % len] ^ nonce[i] for i in 0..15
 *   body = [cmd: 1B][port: 2B BE][at: 1B][addr][optional payload]
 *   (we intentionally send 0-byte initial payload so the worker does not double-write it)
 * - Server ACK: XOR(HMAC-SHA256(key, "OK")[0..15], key)
 * - Data frames (both directions): XOR(rawBytes, key)
 */
object WorkerCrypto {
    const val SUBPROTOCOL = "chat.v2"
    const val CMD_TCP = 1
    const val CMD_UDP = 2

    private const val AT_IPV4 = 1
    private const val AT_DOMAIN = 2
    private const val AT_IPV6 = 3

    private val secureRandom = SecureRandom()
    private val ipv4Regex = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    data class InitHandshake(
        val packet: ByteArray,
        val key: ByteArray,
        val expectedAck: ByteArray
    )

    fun generateNonce(): ByteArray {
        val nonce = ByteArray(16)
        secureRandom.nextBytes(nonce)
        return nonce
    }

    fun deriveKey(uuid: String, nonce: ByteArray): ByteArray {
        require(nonce.size == 16) { "Nonce must be 16 bytes" }
        val tokenBytes = uuid.toByteArray(Charsets.UTF_8)
        require(tokenBytes.isNotEmpty()) { "UUID token must not be empty" }
        val key = ByteArray(16)
        for (i in 0 until 16) {
            key[i] = (tokenBytes[i % tokenBytes.size].toInt() xor nonce[i].toInt()).toByte()
        }
        return key
    }

    fun xorBytes(data: ByteArray, key: ByteArray): ByteArray {
        val out = ByteArray(data.size)
        val kLen = key.size
        for (i in data.indices) {
            out[i] = (data[i].toInt() xor key[i % kLen].toInt()).toByte()
        }
        return out
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun computeExpectedAck(key: ByteArray): ByteArray {
        val ackRaw = hmacSha256(key, "OK".toByteArray(Charsets.UTF_8)).copyOfRange(0, 16)
        return xorBytes(ackRaw, key)
    }

    fun verifyAck(receivedFrame: ByteArray, expectedAck: ByteArray): Boolean {
        if (receivedFrame.size != expectedAck.size) return false
        return MessageDigest.isEqual(receivedFrame, expectedAck)
    }

    fun buildInitHandshake(
        uuid: String,
        targetHost: String,
        targetPort: Int,
        cmd: Int = CMD_TCP,
        nonce: ByteArray = generateNonce()
    ): InitHandshake {
        require(targetPort in 1..65535) { "Invalid port: $targetPort" }
        val cleanHost = targetHost.trim().removePrefix("[").removeSuffix("]")
        require(cleanHost.isNotEmpty()) { "Target host cannot be empty" }

        val key = deriveKey(uuid, nonce)
        val bodyStream = ByteArrayOutputStream(64)
        bodyStream.write(cmd and 0xFF)
        bodyStream.write((targetPort ushr 8) and 0xFF)
        bodyStream.write(targetPort and 0xFF)

        val ipv4Bytes = parseIpv4Literal(cleanHost)
        val ipv6Bytes = if (ipv4Bytes == null && cleanHost.contains(':')) {
            parseIpv6Literal(cleanHost)
        } else null

        when {
            ipv4Bytes != null -> {
                bodyStream.write(AT_IPV4)
                bodyStream.write(ipv4Bytes)
            }
            ipv6Bytes != null -> {
                bodyStream.write(AT_IPV6)
                bodyStream.write(ipv6Bytes)
            }
            else -> {
                val hostBytes = cleanHost.toByteArray(Charsets.UTF_8)
                require(hostBytes.size <= 255) { "Domain name too long: ${hostBytes.size}" }
                bodyStream.write(AT_DOMAIN)
                bodyStream.write(hostBytes.size and 0xFF)
                bodyStream.write(hostBytes)
            }
        }

        val body = bodyStream.toByteArray()
        val encryptedBody = xorBytes(body, key)
        // Worker slices data.subarray(16, data.byteLength - 8)
        val trailer = hmacSha256(key, body).copyOfRange(0, 8)

        val packet = ByteArray(16 + encryptedBody.size + 8)
        System.arraycopy(nonce, 0, packet, 0, 16)
        System.arraycopy(encryptedBody, 0, packet, 16, encryptedBody.size)
        System.arraycopy(trailer, 0, packet, 16 + encryptedBody.size, 8)

        return InitHandshake(
            packet = packet,
            key = key,
            expectedAck = computeExpectedAck(key)
        )
    }

    private fun parseIpv4Literal(host: String): ByteArray? {
        if (!ipv4Regex.matches(host)) return null
        val parts = host.split('.')
        val bytes = ByteArray(4)
        for (i in 0..3) {
            val octet = parts[i].toIntOrNull() ?: return null
            if (octet !in 0..255) return null
            bytes[i] = octet.toByte()
        }
        return bytes
    }

    private fun parseIpv6Literal(host: String): ByteArray? {
        return try {
            val addr = InetAddress.getByName(host)
            if (addr is Inet6Address) addr.address else if (addr is Inet4Address) null else null
        } catch (_: Exception) {
            null
        }
    }
}
