package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSURIResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val priority: UShort,  // Priority
    private val weight: UShort,    // Weight
    private val target: String     // Target URI
) : DNSResourceRecord(name, DNSRRType.URI, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$priority $weight \"$target\""

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(priority)
        rdataList.add(weight)
        rdataList.addAll(target.toByteArray().toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.URI

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSURIResource, Int> {
            var i = offset
            val priority = message.readShort(i)
            i += 2
            val weight = message.readShort(i)
            i += 2
            
            // Parse target URI (rest of the record)
            val targetLength = rdlength - 4
            val target = String(message.sliceArray(i until i + targetLength))
            i += targetLength
            
            return Pair(DNSURIResource(name, dnsClass, ttl, priority, weight, target), i)
        }
    }
}