package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSHTTPSResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val priority: UShort,         // Priority
    private val targetName: String,       // Target name
    private val params: Map<UShort, ByteArray>  // Service parameters
) : DNSResourceRecord(name, DNSRRType.HTTPS, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$priority $targetName ${params.entries.joinToString(" ") { "${it.key}=${it.value.joinToString("") { "%02x".format(it) }}" }}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(priority)
        rdataList.addAll(compressor.compressName(targetName, message).toList())
        
        // Add service parameters
        for ((key, value) in params) {
            rdataList.add(key)
            rdataList.add(value.size.toUShort())
            rdataList.addAll(value.toList())
        }
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.HTTPS

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSHTTPSResource, Int> {
            var i = offset
            val priority = message.readShort(i)
            i += 2
            
            val (targetName, targetEnd) = message.decompressName(i)
            i = targetEnd
            
            // Parse service parameters
            val params = mutableMapOf<UShort, ByteArray>()
            val endOffset = offset + rdlength
            
            while (i < endOffset) {
                val key = message.readShort(i)
                i += 2
                val valueLength = message.readShort(i).toInt()
                i += 2
                val value = message.sliceArray(i until i + valueLength)
                i += valueLength
                params[key] = value
            }
            
            return Pair(DNSHTTPSResource(name, dnsClass, ttl, priority, targetName, params), i)
        }
    }
}