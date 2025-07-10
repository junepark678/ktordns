package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSAFSDBResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val subtype: UShort,   // Subtype
    private val hostname: String   // Hostname
) : DNSResourceRecord(name, DNSRRType.AFSDB, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$subtype $hostname"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(subtype)
        rdataList.addAll(compressor.compressName(hostname, message).toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.AFSDB

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSAFSDBResource, Int> {
            var i = offset
            val subtype = message.readShort(i)
            i += 2
            val (hostname, hostnameEnd) = message.decompressName(i)
            i = hostnameEnd
            
            return Pair(DNSAFSDBResource(name, dnsClass, ttl, subtype, hostname), i)
        }
    }
}