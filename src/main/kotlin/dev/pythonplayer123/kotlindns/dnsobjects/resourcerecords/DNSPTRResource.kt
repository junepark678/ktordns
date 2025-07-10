package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName

class DNSPTRResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val ptrdname: String  // Pointer domain name
) : DNSResourceRecord(name, DNSRRType.PTR, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = ptrdname

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        rddata = compressor.compressName(ptrdname, message)
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.PTR

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSPTRResource, Int> {
            val (ptrdname, newOffset) = message.decompressName(offset)
            return Pair(DNSPTRResource(name, dnsClass, ttl, ptrdname), newOffset)
        }
    }
}