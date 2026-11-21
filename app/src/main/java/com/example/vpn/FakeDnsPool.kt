package com.example.vpn

/**
 * RFC 2544 Fake DNS IPv4 pool (198.18.0.0/15 -> 198.18.0.1 .. 198.19.255.254).
 * Instantly maps queried hostnames to synthetic IPv4 addresses in <0.1ms with zero network I/O,
 * allowing TcpSessionManager to dial the Cloudflare Worker directly with the real domain name.
 */
class FakeDnsPool(private val maxEntries: Int = 4096) {

    companion object {
        private const val SUBNET_PREFIX = 0xC6120000.toInt() // 198.18.0.0
        private const val SUBNET_MASK = 0xFFFE0000.toInt()   // /15 (198.18.0.0 - 198.19.255.255)
        private const val POOL_START = 1                     // 198.18.0.1
        private const val POOL_SIZE = 131_070                // up to 198.19.255.254

        fun isFakeIp(ip: Int): Boolean {
            return (ip and SUBNET_MASK) == SUBNET_PREFIX
        }
    }

    private val lock = Any()
    private val domainToIp = LinkedHashMap<String, Int>(512, 0.75f, true)
    private val ipToDomain = HashMap<Int, String>(512)
    private var nextCursor = POOL_START

    fun allocateOrGet(domain: String): Int {
        val normalized = domain.trim().trimEnd('.').lowercase()
        synchronized(lock) {
            domainToIp[normalized]?.let { return it }

            // Evict least-recently-used entry if pool cap reached
            if (domainToIp.size >= maxEntries) {
                val eldest = domainToIp.entries.iterator().next()
                val recycledIp = eldest.value
                domainToIp.remove(eldest.key)
                ipToDomain.remove(recycledIp)
                domainToIp[normalized] = recycledIp
                ipToDomain[recycledIp] = normalized
                return recycledIp
            }

            var attempts = 0
            while (attempts < POOL_SIZE) {
                val candidateOffset = nextCursor
                nextCursor = if (nextCursor >= POOL_SIZE) POOL_START else nextCursor + 1
                val candidateIp = SUBNET_PREFIX or (candidateOffset and 0x1FFFF)
                if (!ipToDomain.containsKey(candidateIp)) {
                    domainToIp[normalized] = candidateIp
                    ipToDomain[candidateIp] = normalized
                    return candidateIp
                }
                attempts++
            }

            // Fallback recycle if completely full
            val eldest = domainToIp.entries.iterator().next()
            val recycledIp = eldest.value
            domainToIp.remove(eldest.key)
            domainToIp[normalized] = recycledIp
            ipToDomain[recycledIp] = normalized
            return recycledIp
        }
    }

    fun lookupDomain(ip: Int): String? {
        if (!isFakeIp(ip)) return null
        synchronized(lock) {
            val domain = ipToDomain[ip] ?: return null
            // Touch LRU order
            domainToIp[domain]
            return domain
        }
    }

    fun clear() {
        synchronized(lock) {
            domainToIp.clear()
            ipToDomain.clear()
            nextCursor = POOL_START
        }
    }
}
