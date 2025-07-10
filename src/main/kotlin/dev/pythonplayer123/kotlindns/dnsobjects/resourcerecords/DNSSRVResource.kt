package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSSRVResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val priority: UShort,   // Priority
    private val weight: UShort,     // Weight
    private val port: UShort,       // Port number
    private val target: String      // Target hostname
) : DNSResourceRecord(name, DNSRRType.SRV, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$priority $weight $port $target"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(priority)
        rdataList.add(weight)
        rdataList.add(port)
        rdataList.addAll(compressor.compressName(target, message).toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.SRV

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSSRVResource, Int> {
            var i = offset
            val priority = message.readShort(i)
            i += 2
            val weight = message.readShort(i)
            i += 2
            val port = message.readShort(i)
            i += 2
            val (target, targetEnd) = message.decompressName(i)
            
            return Pair(DNSSRVResource(name, dnsClass, ttl, priority, weight, port, target), targetEnd)
        }
    }
}