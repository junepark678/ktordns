package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add

class DNSEUI64Resource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val eui64: ByteArray  // 64-bit EUI
) : DNSResourceRecord(name, DNSRRType.EUI64, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = eui64.joinToString("-") { "%02x".format(it) }

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        rddata = eui64
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.EUI64

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSEUI64Resource, Int> {
            val eui64 = message.sliceArray(offset until offset + 8)
            return Pair(DNSEUI64Resource(name, dnsClass, ttl, eui64), offset + 8)
        }
    }
}