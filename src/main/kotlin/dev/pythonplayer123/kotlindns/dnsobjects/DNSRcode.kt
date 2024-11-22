package dev.pythonplayer123.kotlindns.dnsobjects

enum class DNSRcode(val rcode: UByte) {
    NOERROR(0x0u),
    FORMERR(0x1u),
    SERVFAIL(0x2u),
    NXDOMAIN(0x3u);

    companion object {
        fun fromRcode(rcode: UByte): DNSRcode {
            return entries.find { it.rcode == rcode }!!
        }
    }
}
