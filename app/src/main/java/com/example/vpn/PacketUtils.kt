package com.example.vpn

import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger

object PacketUtils {
    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17

    const val TCP_FIN = 0x01
    const val TCP_SYN = 0x02
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08
    const val TCP_ACK = 0x10

    private val ipIdGenerator = AtomicInteger(1)

    data class Ipv4Header(
        val headerLength: Int,
        val totalLength: Int,
        val protocol: Int,
        val srcIp: Int,
        val dstIp: Int
    )

    data class TcpHeader(
        val srcPort: Int,
        val dstPort: Int,
        val seqNum: Long,
        val ackNum: Long,
        val headerLength: Int,
        val flags: Int,
        val windowSize: Int,
        val payloadOffset: Int,
        val payloadLength: Int
    )

    data class UdpHeader(
        val srcPort: Int,
        val dstPort: Int,
        val payloadOffset: Int,
        val payloadLength: Int
    )

    fun parseIpv4Header(packet: ByteArray, length: Int): Ipv4Header? {
        if (length < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > length) return null
        val totalLength = readUInt16(packet, 2).coerceAtMost(length)
        if (totalLength < ihl) return null
        val protocol = packet[9].toInt() and 0xFF
        val srcIp = readInt32(packet, 12)
        val dstIp = readInt32(packet, 16)
        return Ipv4Header(
            headerLength = ihl,
            totalLength = totalLength,
            protocol = protocol,
            srcIp = srcIp,
            dstIp = dstIp
        )
    }

    fun parseTcpHeader(packet: ByteArray, ip: Ipv4Header): TcpHeader? {
        val offset = ip.headerLength
        if (ip.totalLength < offset + 20) return null
        val srcPort = readUInt16(packet, offset)
        val dstPort = readUInt16(packet, offset + 2)
        val seqNum = readUInt32(packet, offset + 4)
        val ackNum = readUInt32(packet, offset + 8)
        val dataOffset = ((packet[offset + 12].toInt() ushr 4) and 0x0F) * 4
        if (dataOffset < 20 || offset + dataOffset > ip.totalLength) return null
        val flags = packet[offset + 13].toInt() and 0xFF
        val windowSize = readUInt16(packet, offset + 14)
        val payloadOffset = offset + dataOffset
        val payloadLength = (ip.totalLength - payloadOffset).coerceAtLeast(0)
        return TcpHeader(
            srcPort = srcPort,
            dstPort = dstPort,
            seqNum = seqNum,
            ackNum = ackNum,
            headerLength = dataOffset,
            flags = flags,
            windowSize = windowSize,
            payloadOffset = payloadOffset,
            payloadLength = payloadLength
        )
    }

    fun parseUdpHeader(packet: ByteArray, ip: Ipv4Header): UdpHeader? {
        val offset = ip.headerLength
        if (ip.totalLength < offset + 8) return null
        val srcPort = readUInt16(packet, offset)
        val dstPort = readUInt16(packet, offset + 2)
        val udpLen = readUInt16(packet, offset + 4)
        val payloadOffset = offset + 8
        val maxAvail = (ip.totalLength - payloadOffset).coerceAtLeast(0)
        val payloadLength = (udpLen - 8).coerceIn(0, maxAvail)
        return UdpHeader(
            srcPort = srcPort,
            dstPort = dstPort,
            payloadOffset = payloadOffset,
            payloadLength = payloadLength
        )
    }

    fun buildIpv4TcpPacket(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        windowSize: Int = 65535,
        payload: ByteArray = ByteArray(0),
        payloadOffset: Int = 0,
        payloadLength: Int = payload.size
    ): ByteArray {
        val ipHeaderLen = 20
        val tcpHeaderLen = 20
        val totalLen = ipHeaderLen + tcpHeaderLen + payloadLength
        val packet = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(packet)

        // IPv4 Header
        buf.put(0x45.toByte()) // Version 4, IHL 5 (20 bytes)
        buf.put(0x00.toByte()) // DSCP/ECN
        buf.putShort(totalLen.toShort())
        buf.putShort((ipIdGenerator.getAndIncrement() and 0xFFFF).toShort())
        buf.putShort(0x4000.toShort()) // Don't Fragment
        buf.put(64.toByte()) // TTL
        buf.put(PROTOCOL_TCP.toByte())
        buf.putShort(0) // IP checksum placeholder
        buf.putInt(srcIp)
        buf.putInt(dstIp)

        // TCP Header
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putInt((seqNum and 0xFFFFFFFFL).toInt())
        buf.putInt((ackNum and 0xFFFFFFFFL).toInt())
        buf.put(0x50.toByte()) // Data offset = 5 (20 bytes)
        buf.put((flags and 0xFF).toByte())
        buf.putShort((windowSize and 0xFFFF).toShort())
        buf.putShort(0) // TCP checksum placeholder
        buf.putShort(0) // Urgent pointer

        if (payloadLength > 0) {
            System.arraycopy(payload, payloadOffset, packet, ipHeaderLen + tcpHeaderLen, payloadLength)
        }

        // Compute IPv4 header checksum
        val ipChecksum = computeChecksum(packet, 0, ipHeaderLen)
        packet[10] = (ipChecksum ushr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        // Compute TCP checksum with IPv4 pseudo-header
        val tcpChecksum = computeTransportChecksum(
            srcIp = srcIp,
            dstIp = dstIp,
            protocol = PROTOCOL_TCP,
            packet = packet,
            transportOffset = ipHeaderLen,
            transportLength = tcpHeaderLen + payloadLength
        )
        packet[ipHeaderLen + 16] = (tcpChecksum ushr 8).toByte()
        packet[ipHeaderLen + 17] = (tcpChecksum and 0xFF).toByte()

        return packet
    }

    fun buildIpv4UdpPacket(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeaderLen = 20
        val udpLen = 8 + payload.size
        val totalLen = ipHeaderLen + udpLen
        val packet = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(packet)

        // IPv4 Header
        buf.put(0x45.toByte())
        buf.put(0x00.toByte())
        buf.putShort(totalLen.toShort())
        buf.putShort((ipIdGenerator.getAndIncrement() and 0xFFFF).toShort())
        buf.putShort(0x4000.toShort())
        buf.put(64.toByte())
        buf.put(PROTOCOL_UDP.toByte())
        buf.putShort(0)
        buf.putInt(srcIp)
        buf.putInt(dstIp)

        // UDP Header
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort())
        buf.putShort(0) // UDP checksum placeholder
        System.arraycopy(payload, 0, packet, ipHeaderLen + 8, payload.size)

        val ipChecksum = computeChecksum(packet, 0, ipHeaderLen)
        packet[10] = (ipChecksum ushr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        val udpChecksum = computeTransportChecksum(
            srcIp = srcIp,
            dstIp = dstIp,
            protocol = PROTOCOL_UDP,
            packet = packet,
            transportOffset = ipHeaderLen,
            transportLength = udpLen
        )
        val finalUdpChecksum = if (udpChecksum == 0) 0xFFFF else udpChecksum
        packet[ipHeaderLen + 6] = (finalUdpChecksum ushr 8).toByte()
        packet[ipHeaderLen + 7] = (finalUdpChecksum and 0xFF).toByte()

        return packet
    }

    fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    fun computeTransportChecksum(
        srcIp: Int,
        dstIp: Int,
        protocol: Int,
        packet: ByteArray,
        transportOffset: Int,
        transportLength: Int
    ): Int {
        var sum = 0L
        // Pseudo-header
        sum += (srcIp ushr 16) and 0xFFFF
        sum += srcIp and 0xFFFF
        sum += (dstIp ushr 16) and 0xFFFF
        sum += dstIp and 0xFFFF
        sum += protocol and 0xFF
        sum += transportLength and 0xFFFF

        // Transport header + payload
        var i = transportOffset
        val end = transportOffset + transportLength
        while (i + 1 < end) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFFL).toInt()
    }

    /**
     * Extracts Server Name Indication (SNI) from a TLS ClientHello record so the Worker
     * receives the true domain name instead of only a numeric IP.
     */
    fun extractTlsSni(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): String? {
        if (length < 43) return null
        // TLS Record: ContentType = Handshake (0x16), Version = 0x03 0x00..0x04
        if ((data[offset].toInt() and 0xFF) != 0x16) return null
        if ((data[offset + 1].toInt() and 0xFF) != 0x03) return null

        var pos = offset + 5
        val end = offset + length
        if (pos + 4 > end) return null
        // HandshakeType = ClientHello (0x01)
        if ((data[pos].toInt() and 0xFF) != 0x01) return null
        pos += 4 // type(1) + length(3)
        pos += 2 + 32 // client_version(2) + random(32)
        if (pos + 1 > end) return null

        // Session ID
        val sessionIdLen = data[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen
        if (pos + 2 > end) return null

        // Cipher suites
        val cipherSuitesLen = readUInt16(data, pos)
        pos += 2 + cipherSuitesLen
        if (pos + 1 > end) return null

        // Compression methods
        val compLen = data[pos].toInt() and 0xFF
        pos += 1 + compLen
        if (pos + 2 > end) return null

        // Extensions
        val extTotalLen = readUInt16(data, pos)
        pos += 2
        val extEnd = (pos + extTotalLen).coerceAtMost(end)

        while (pos + 4 <= extEnd) {
            val extType = readUInt16(data, pos)
            val extLen = readUInt16(data, pos + 2)
            pos += 4
            if (pos + extLen > extEnd) break
            if (extType == 0x0000 && extLen >= 5) { // server_name extension
                var sniPos = pos + 2 // skip server_name_list length
                val sniEnd = pos + extLen
                while (sniPos + 3 <= sniEnd) {
                    val nameType = data[sniPos].toInt() and 0xFF
                    val nameLen = readUInt16(data, sniPos + 1)
                    sniPos += 3
                    if (nameType == 0 && sniPos + nameLen <= sniEnd && nameLen in 1..253) {
                        val host = String(data, sniPos, nameLen, Charsets.US_ASCII).trim()
                        if (host.contains('.')) return host
                    }
                    sniPos += nameLen
                }
            }
            pos += extLen
        }
        return null
    }

    /**
     * Extracts the Host header from a cleartext HTTP/1.x request payload.
     */
    fun extractHttpHost(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): String? {
        if (length < 16) return null
        val scanLen = length.coerceAtMost(1024)
        val text = String(data, offset, scanLen, Charsets.ISO_8859_1)
        val firstLineEnd = text.indexOf("\r\n")
        if (firstLineEnd <= 0) return null
        val firstLine = text.substring(0, firstLineEnd)
        val isHttp = firstLine.startsWith("GET ") ||
            firstLine.startsWith("POST ") ||
            firstLine.startsWith("HEAD ") ||
            firstLine.startsWith("PUT ") ||
            firstLine.startsWith("DELETE ") ||
            firstLine.startsWith("OPTIONS ") ||
            firstLine.startsWith("PATCH ")
        if (!isHttp) return null

        val lines = text.split("\r\n")
        for (line in lines.drop(1)) {
            if (line.isEmpty()) break
            if (line.startsWith("Host:", ignoreCase = true)) {
                val hostVal = line.substring(5).trim().substringBefore(':').trim()
                if (hostVal.isNotEmpty() && hostVal.length <= 253) return hostVal
            }
        }
        return null
    }

    fun ipIntToString(ip: Int): String {
        return "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"
    }

    fun ipv4BytesToInt(bytes: ByteArray, offset: Int): Int {
        return ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
    }

    fun readUInt16(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    fun readInt32(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
            ((data[offset + 1].toInt() and 0xFF) shl 16) or
            ((data[offset + 2].toInt() and 0xFF) shl 8) or
            (data[offset + 3].toInt() and 0xFF)
    }

    fun readUInt32(data: ByteArray, offset: Int): Long {
        return readInt32(data, offset).toLong() and 0xFFFFFFFFL
    }
}
