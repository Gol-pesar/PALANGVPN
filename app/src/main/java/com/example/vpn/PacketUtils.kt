package com.example.vpn

import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger

object PacketUtils {
    const val PROTOCOL_ICMP = 1
    const val PROTOCOL_TCP = 6
    const val PROTOCOL_UDP = 17

    const val TCP_FIN = 0x01
    const val TCP_SYN = 0x02
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08
    const val TCP_ACK = 0x10

    const val DEFAULT_MSS = 1360
    const val DEFAULT_WINDOW_SCALE = 7 // 65535 << 7 = ~8MB advertised receive window

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
        val windowScaleShift: Int?,
        val mss: Int?,
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

        var windowScale: Int? = null
        var mss: Int? = null
        if (dataOffset > 20 && (flags and TCP_SYN) != 0) {
            var optPos = offset + 20
            val optEnd = offset + dataOffset
            while (optPos < optEnd) {
                val kind = packet[optPos].toInt() and 0xFF
                if (kind == 0) break // End of options
                if (kind == 1) { // NOP
                    optPos++
                    continue
                }
                if (optPos + 1 >= optEnd) break
                val len = packet[optPos + 1].toInt() and 0xFF
                if (len < 2 || optPos + len > optEnd) break
                when (kind) {
                    2 -> if (len == 4) {
                        mss = readUInt16(packet, optPos + 2)
                    }
                    3 -> if (len == 3) {
                        windowScale = (packet[optPos + 2].toInt() and 0xFF).coerceAtMost(14)
                    }
                }
                optPos += len
            }
        }

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
            windowScaleShift = windowScale,
            mss = mss,
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

    /**
     * Builds an IPv4/TCP packet. When [includeSynOptions] is true (for SYN-ACK), attaches
     * MSS (1360) and optional Window Scale options so Android negotiates large windows cleanly.
     */
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
        payloadLength: Int = payload.size,
        includeSynOptions: Boolean = false,
        windowScaleShift: Int? = null,
        mssValue: Int = DEFAULT_MSS
    ): ByteArray {
        val ipHeaderLen = 20
        val optionsLen = if (includeSynOptions) {
            if (windowScaleShift != null) 8 else 4
        } else 0
        val tcpHeaderLen = 20 + optionsLen
        val totalLen = ipHeaderLen + tcpHeaderLen + payloadLength
        val packet = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(packet)

        // IPv4 Header
        buf.put(0x45.toByte())
        buf.put(0x00.toByte())
        buf.putShort(totalLen.toShort())
        buf.putShort((ipIdGenerator.getAndIncrement() and 0xFFFF).toShort())
        buf.putShort(0x4000.toShort()) // Don't Fragment
        buf.put(64.toByte())
        buf.put(PROTOCOL_TCP.toByte())
        buf.putShort(0)
        buf.putInt(srcIp)
        buf.putInt(dstIp)

        // TCP Header
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putInt((seqNum and 0xFFFFFFFFL).toInt())
        buf.putInt((ackNum and 0xFFFFFFFFL).toInt())
        buf.put(((tcpHeaderLen / 4) shl 4).toByte())
        buf.put((flags and 0xFF).toByte())
        buf.putShort((windowSize and 0xFFFF).toShort())
        buf.putShort(0)
        buf.putShort(0)

        if (includeSynOptions) {
            // Option 2: MSS (4 bytes)
            buf.put(2.toByte())
            buf.put(4.toByte())
            buf.putShort(mssValue.toShort())
            if (windowScaleShift != null) {
                // Option 1: NOP + Option 3: Window Scale (3 bytes) = 4 bytes total
                buf.put(1.toByte())
                buf.put(3.toByte())
                buf.put(3.toByte())
                buf.put(windowScaleShift.coerceIn(0, 14).toByte())
            }
        }

        if (payloadLength > 0) {
            System.arraycopy(payload, payloadOffset, packet, ipHeaderLen + tcpHeaderLen, payloadLength)
        }

        val ipChecksum = computeChecksum(packet, 0, ipHeaderLen)
        packet[10] = (ipChecksum ushr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

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

        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putShort(udpLen.toShort())
        buf.putShort(0)
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

    /**
     * Builds an ICMP Destination Unreachable / Port Unreachable (Type 3, Code 3) reply for
     * unsupported UDP flows (such as QUIC UDP/443) so Chrome/Google apps immediately fall back
     * to TCP/443 instead of stalling for 5–10 seconds waiting on QUIC timeouts.
     */
    fun buildIpv4IcmpPortUnreachable(
        originalPacket: ByteArray,
        ip: Ipv4Header
    ): ByteArray {
        val quotedLen = (ip.headerLength + 8).coerceAtMost(ip.totalLength)
        val ipHeaderLen = 20
        val icmpLen = 8 + quotedLen
        val totalLen = ipHeaderLen + icmpLen
        val packet = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(packet)

        // IPv4 Header (src = original dst, dst = original src)
        buf.put(0x45.toByte())
        buf.put(0x00.toByte())
        buf.putShort(totalLen.toShort())
        buf.putShort((ipIdGenerator.getAndIncrement() and 0xFFFF).toShort())
        buf.putShort(0x0000.toShort())
        buf.put(64.toByte())
        buf.put(PROTOCOL_ICMP.toByte())
        buf.putShort(0)
        buf.putInt(ip.dstIp)
        buf.putInt(ip.srcIp)

        // ICMP Header: Type 3 (Destination Unreachable), Code 3 (Port Unreachable), 4 zero bytes
        buf.put(3.toByte())
        buf.put(3.toByte())
        buf.putShort(0) // checksum placeholder
        buf.putInt(0)   // unused

        System.arraycopy(originalPacket, 0, packet, ipHeaderLen + 8, quotedLen)

        val ipChecksum = computeChecksum(packet, 0, ipHeaderLen)
        packet[10] = (ipChecksum ushr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        val icmpChecksum = computeChecksum(packet, ipHeaderLen, icmpLen)
        packet[ipHeaderLen + 2] = (icmpChecksum ushr 8).toByte()
        packet[ipHeaderLen + 3] = (icmpChecksum and 0xFF).toByte()

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
        sum += (srcIp ushr 16) and 0xFFFF
        sum += srcIp and 0xFFFF
        sum += (dstIp ushr 16) and 0xFFFF
        sum += dstIp and 0xFFFF
        sum += protocol and 0xFF
        sum += transportLength and 0xFFFF

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

    fun extractTlsSni(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): String? {
        if (length < 43) return null
        if ((data[offset].toInt() and 0xFF) != 0x16) return null
        if ((data[offset + 1].toInt() and 0xFF) != 0x03) return null

        var pos = offset + 5
        val end = offset + length
        if (pos + 4 > end) return null
        if ((data[pos].toInt() and 0xFF) != 0x01) return null
        pos += 4
        pos += 2 + 32
        if (pos + 1 > end) return null

        val sessionIdLen = data[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen
        if (pos + 2 > end) return null

        val cipherSuitesLen = readUInt16(data, pos)
        pos += 2 + cipherSuitesLen
        if (pos + 1 > end) return null

        val compLen = data[pos].toInt() and 0xFF
        pos += 1 + compLen
        if (pos + 2 > end) return null

        val extTotalLen = readUInt16(data, pos)
        pos += 2
        val extEnd = (pos + extTotalLen).coerceAtMost(end)

        while (pos + 4 <= extEnd) {
            val extType = readUInt16(data, pos)
            val extLen = readUInt16(data, pos + 2)
            pos += 4
            if (pos + extLen > extEnd) break
            if (extType == 0x0000 && extLen >= 5) {
                var sniPos = pos + 2
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

    /** Signed 32-bit modular TCP sequence difference: positive if a is ahead of b. */
    fun seqDiff(a: Long, b: Long): Long {
        return ((a - b).toInt()).toLong()
    }
}
