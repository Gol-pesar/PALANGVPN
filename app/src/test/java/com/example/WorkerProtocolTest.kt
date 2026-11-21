package com.example

import com.example.vpn.PacketUtils
import com.example.vpn.protocol.WorkerConfig
import com.example.vpn.protocol.WorkerCrypto
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class WorkerProtocolTest {

    private val defaultUuid = "63ae8279-fafa-4dd0-b2ef-9d6a4ec3ffdd"

    /**
     * Exact Kotlin mirror of worker_534a9c26.js parseInit() to guarantee 100% wire compatibility.
     */
    private fun workerJsParseInit(data: ByteArray, token: String): Triple<String, Int, ByteArray>? {
        if (data.size < 16 + 1 + 2 + 1 + 8) return null
        val nonce = data.copyOfRange(0, 16)
        val tb = token.toByteArray(Charsets.UTF_8)
        val key = ByteArray(16)
        for (i in 0 until 16) {
            key[i] = (tb[i % tb.size].toInt() xor nonce[i].toInt()).toByte()
        }
        val enc = data.copyOfRange(16, data.size - 8)
        val body = WorkerCrypto.xorBytes(enc, key)
        var p = 0
        val cmd = body[p++].toInt() and 0xFF
        if (cmd != 1 && cmd != 2) return null
        val port = ((body[p].toInt() and 0xFF) shl 8) or (body[p + 1].toInt() and 0xFF)
        p += 2
        val at = body[p++].toInt() and 0xFF
        val host = when (at) {
            1 -> {
                val h = "${body[p].toInt() and 0xFF}.${body[p + 1].toInt() and 0xFF}.${body[p + 2].toInt() and 0xFF}.${body[p + 3].toInt() and 0xFF}"
                p += 4
                h
            }
            2 -> {
                val l = body[p++].toInt() and 0xFF
                val h = String(body, p, l, Charsets.UTF_8)
                p += l
                h
            }
            3 -> {
                val parts = mutableListOf<String>()
                for (i in 0 until 8) {
                    val v = ((body[p + i * 2].toInt() and 0xFF) shl 8) or (body[p + i * 2 + 1].toInt() and 0xFF)
                    parts.add(v.toString(16))
                }
                p += 16
                parts.joinToString(":")
            }
            else -> return null
        }
        if (host.isEmpty()) return null
        val payload = body.copyOfRange(p, body.size)
        return Triple(host, port, payload)
    }

    @Test
    fun initHandshake_domainTarget_matchesWorkerParseInit() {
        val nonce = ByteArray(16) { (it * 17 + 3).toByte() }
        val hs = WorkerCrypto.buildInitHandshake(
            uuid = defaultUuid,
            targetHost = "cp.cloudflare.com",
            targetPort = 443,
            nonce = nonce
        )

        val parsed = workerJsParseInit(hs.packet, defaultUuid)
        assertNotNull(parsed)
        assertEquals("cp.cloudflare.com", parsed!!.first)
        assertEquals(443, parsed.second)
        // Initial payload MUST be empty so worker does not double-write it
        assertEquals(0, parsed.third.size)
    }

    @Test
    fun initHandshake_ipv4Target_matchesWorkerParseInit() {
        val nonce = ByteArray(16) { (it + 1).toByte() }
        val hs = WorkerCrypto.buildInitHandshake(
            uuid = defaultUuid,
            targetHost = "1.1.1.1",
            targetPort = 53,
            nonce = nonce
        )

        val parsed = workerJsParseInit(hs.packet, defaultUuid)
        assertNotNull(parsed)
        assertEquals("1.1.1.1", parsed!!.first)
        assertEquals(53, parsed.second)
        assertEquals(0, parsed.third.size)
    }

    @Test
    fun ackVerification_matchesWorkerHmacSha256AndXor() {
        val nonce = ByteArray(16) { 0x5A.toByte() }
        val hs = WorkerCrypto.buildInitHandshake(
            uuid = defaultUuid,
            targetHost = "example.com",
            targetPort = 80,
            nonce = nonce
        )

        val workerSideAck = WorkerCrypto.xorBytes(
            WorkerCrypto.hmacSha256(hs.key, "OK".toByteArray(Charsets.UTF_8)).copyOfRange(0, 16),
            hs.key
        )
        assertTrue(WorkerCrypto.verifyAck(workerSideAck, hs.expectedAck))

        val tampered = workerSideAck.copyOf()
        tampered[0] = (tampered[0].toInt() xor 0xFF).toByte()
        assertFalse(WorkerCrypto.verifyAck(tampered, hs.expectedAck))
    }

    @Test
    fun xorRoundTrip_preservesArbitraryStreamData() {
        val key = ByteArray(16) { (it * 13).toByte() }
        val plaintext = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        val encrypted = WorkerCrypto.xorBytes(plaintext, key)
        val decrypted = WorkerCrypto.xorBytes(encrypted, key)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun workerConfig_parsesWorkerUrlAndCleanIpVariants() {
        val cfg1 = WorkerConfig(
            workerUrl = "https://my-edge.user.workers.dev/ws",
            uuid = defaultUuid,
            cleanIp = "104.16.132.229:8443"
        )
        val ep1 = cfg1.parseEndpoint()
        assertNotNull(ep1)
        assertEquals("wss://my-edge.user.workers.dev:8443/ws", ep1!!.wsUrl)
        assertEquals("my-edge.user.workers.dev", ep1.workerHost)
        assertEquals(8443, ep1.port)
        assertEquals("104.16.132.229", ep1.cleanIpHost)

        val cfg2 = WorkerConfig(
            workerUrl = "plain-worker.workers.dev",
            uuid = defaultUuid,
            cleanIp = ""
        )
        val ep2 = cfg2.parseEndpoint()
        assertNotNull(ep2)
        assertEquals("wss://plain-worker.workers.dev/", ep2!!.wsUrl)
        assertEquals(443, ep2.port)
        assertEquals(null, ep2.cleanIpHost)
    }

    @Test
    fun packetUtils_tcpRoundTripAndChecksumValid() {
        val srcIp = 0x0A000002 // 10.0.0.2
        val dstIp = 0x01010101 // 1.1.1.1
        val payload = "hello-tunnel".toByteArray()
        val pkt = PacketUtils.buildIpv4TcpPacket(
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = 54321,
            dstPort = 443,
            seqNum = 1000L,
            ackNum = 2000L,
            flags = PacketUtils.TCP_PSH or PacketUtils.TCP_ACK,
            payload = payload
        )

        val ip = PacketUtils.parseIpv4Header(pkt, pkt.size)
        assertNotNull(ip)
        assertEquals(srcIp, ip!!.srcIp)
        assertEquals(dstIp, ip.dstIp)
        assertEquals(0, PacketUtils.computeChecksum(pkt, 0, ip.headerLength))

        val tcp = PacketUtils.parseTcpHeader(pkt, ip)
        assertNotNull(tcp)
        assertEquals(54321, tcp!!.srcPort)
        assertEquals(443, tcp.dstPort)
        assertEquals(1000L, tcp.seqNum)
        assertEquals(2000L, tcp.ackNum)
        assertEquals(payload.size, tcp.payloadLength)
        assertEquals(
            0,
            PacketUtils.computeTransportChecksum(
                srcIp = srcIp,
                dstIp = dstIp,
                protocol = PacketUtils.PROTOCOL_TCP,
                packet = pkt,
                transportOffset = ip.headerLength,
                transportLength = ip.totalLength - ip.headerLength
            )
        )
    }

    @Test
    fun packetUtils_extractsTlsSniAndHttpHost() {
        // Minimal synthetic TLS 1.2 ClientHello containing server_name = "api.github.com"
        val host = "api.github.com".toByteArray(Charsets.US_ASCII)
        val sniExtData = ByteArrayOutputStream().apply {
            val listLen = 3 + host.size
            write((listLen ushr 8) and 0xFF); write(listLen and 0xFF)
            write(0x00) // host_name type
            write((host.size ushr 8) and 0xFF); write(host.size and 0xFF)
            write(host)
        }.toByteArray()

        val clientHelloBody = ByteArrayOutputStream().apply {
            write(0x03); write(0x03) // TLS 1.2
            write(ByteArray(32)) // Random
            write(0x00) // Session ID len = 0
            write(0x00); write(0x02); write(0x13); write(0x01) // Cipher suites
            write(0x01); write(0x00) // Compression
            val extTotal = 4 + sniExtData.size
            write((extTotal ushr 8) and 0xFF); write(extTotal and 0xFF)
            write(0x00); write(0x00) // server_name extension type
            write((sniExtData.size ushr 8) and 0xFF); write(sniExtData.size and 0xFF)
            write(sniExtData)
        }.toByteArray()

        val tlsRecord = ByteArrayOutputStream().apply {
            val hsLen = clientHelloBody.size
            val recLen = 4 + hsLen
            write(0x16); write(0x03); write(0x01)
            write((recLen ushr 8) and 0xFF); write(recLen and 0xFF)
            write(0x01) // ClientHello
            write((hsLen ushr 16) and 0xFF); write((hsLen ushr 8) and 0xFF); write(hsLen and 0xFF)
            write(clientHelloBody)
        }.toByteArray()

        assertEquals("api.github.com", PacketUtils.extractTlsSni(tlsRecord))
        assertEquals(
            "example.org",
            PacketUtils.extractHttpHost("GET / HTTP/1.1\r\nHost: example.org:80\r\n\r\n".toByteArray())
        )
    }

    @Test
    fun packetUtils_synAckOptionsAndIcmpUnreachableAreValid() {
        val synAck = PacketUtils.buildIpv4TcpPacket(
            srcIp = 0x08080808,
            dstIp = 0x0A000002,
            srcPort = 443,
            dstPort = 51234,
            seqNum = 9000L,
            ackNum = 1001L,
            flags = PacketUtils.TCP_SYN or PacketUtils.TCP_ACK,
            includeSynOptions = true,
            windowScaleShift = PacketUtils.DEFAULT_WINDOW_SCALE,
            mssValue = PacketUtils.DEFAULT_MSS
        )

        val ip = PacketUtils.parseIpv4Header(synAck, synAck.size)
        assertNotNull(ip)
        assertEquals(0, PacketUtils.computeChecksum(synAck, 0, ip!!.headerLength))

        val tcp = PacketUtils.parseTcpHeader(synAck, ip)
        assertNotNull(tcp)
        assertEquals(28, tcp!!.headerLength)
        assertEquals(PacketUtils.DEFAULT_MSS, tcp.mss)
        assertEquals(PacketUtils.DEFAULT_WINDOW_SCALE, tcp.windowScaleShift)
        assertEquals(
            0,
            PacketUtils.computeTransportChecksum(
                srcIp = ip.srcIp,
                dstIp = ip.dstIp,
                protocol = PacketUtils.PROTOCOL_TCP,
                packet = synAck,
                transportOffset = ip.headerLength,
                transportLength = ip.totalLength - ip.headerLength
            )
        )

        val quicUdp = PacketUtils.buildIpv4UdpPacket(
            srcIp = 0x0A000002,
            dstIp = 0x8EFAA04E.toInt(),
            srcPort = 55000,
            dstPort = 443,
            payload = ByteArray(32) { 0x42 }
        )
        val quicIp = PacketUtils.parseIpv4Header(quicUdp, quicUdp.size)!!
        val icmp = PacketUtils.buildIpv4IcmpPortUnreachable(quicUdp, quicIp)
        val icmpIp = PacketUtils.parseIpv4Header(icmp, icmp.size)!!
        assertEquals(PacketUtils.PROTOCOL_ICMP, icmpIp.protocol)
        assertEquals(0, PacketUtils.computeChecksum(icmp, 0, icmpIp.headerLength))
        assertEquals(0, PacketUtils.computeChecksum(icmp, icmpIp.headerLength, icmpIp.totalLength - icmpIp.headerLength))
        assertEquals(3, icmp[icmpIp.headerLength].toInt() and 0xFF)
        assertEquals(3, icmp[icmpIp.headerLength + 1].toInt() and 0xFF)

        assertTrue(PacketUtils.seqDiff(0x00000005L, 0xFFFFFFFBL) == 10L)
        assertTrue(PacketUtils.seqDiff(0xFFFFFFFBL, 0x00000005L) == -10L)
    }

    @Test
    fun fakeDnsPool_allocatesAndResolvesRfc2544Addresses() {
        val pool = com.example.vpn.FakeDnsPool(maxEntries = 4)
        val ipGoogle = pool.allocateOrGet("www.google.com")
        val ipGoogleAgain = pool.allocateOrGet("WWW.GOOGLE.COM.")
        val ipYoutube = pool.allocateOrGet("youtube.com")

        assertEquals(ipGoogle, ipGoogleAgain)
        assertTrue(com.example.vpn.FakeDnsPool.isFakeIp(ipGoogle))
        assertTrue(com.example.vpn.FakeDnsPool.isFakeIp(ipYoutube))
        assertFalse(com.example.vpn.FakeDnsPool.isFakeIp(0x08080808))
        assertEquals("www.google.com", pool.lookupDomain(ipGoogle))
        assertEquals("youtube.com", pool.lookupDomain(ipYoutube))
    }
}
