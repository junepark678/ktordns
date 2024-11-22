package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.toDNSLabel

class DNSCNAMEResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val cname: String
) : DNSResourceRecord(name, value, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = cname

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        rddata = compressor.compressName(cname, message)
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.CNAME

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSCNAMEResource, Int> {
            val (a, i) = message.decompressName(offset)
            return Pair(DNSCNAMEResource(name, dnsClass, ttl, a), i)
        }

    }
}
