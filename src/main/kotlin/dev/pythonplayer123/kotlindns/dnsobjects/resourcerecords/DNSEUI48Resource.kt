package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add

class DNSEUI48Resource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val eui48: ByteArray  // 48-bit EUI
) : DNSResourceRecord(name, DNSRRType.EUI48, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = eui48.joinToString("-") { "%02x".format(it) }

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        rddata = eui48
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.EUI48

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSEUI48Resource, Int> {
            val eui48 = message.sliceArray(offset until offset + 6)
            return Pair(DNSEUI48Resource(name, dnsClass, ttl, eui48), offset + 6)
        }
    }
}