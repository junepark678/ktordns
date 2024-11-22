package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass

interface DNSResourceCompanionObject {
    val value: DNSRRType
    fun parse(
        name: String,
        dnsClass: DNSQueryClass,
        ttl: UInt,
        message: ByteArray,
        offset: Int,
        rdlength: Int
    ): Pair<DNSResourceRecord, Int>
}
