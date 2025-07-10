package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSKXResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val preference: UShort,  // Preference
    private val exchanger: String    // Key exchanger
) : DNSResourceRecord(name, DNSRRType.KX, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$preference $exchanger"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(preference)
        rdataList.addAll(compressor.compressName(exchanger, message).toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.KX

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSKXResource, Int> {
            var i = offset
            val preference = message.readShort(i)
            i += 2
            val (exchanger, exchangerEnd) = message.decompressName(i)
            i = exchangerEnd
            
            return Pair(DNSKXResource(name, dnsClass, ttl, preference, exchanger), i)
        }
    }
}