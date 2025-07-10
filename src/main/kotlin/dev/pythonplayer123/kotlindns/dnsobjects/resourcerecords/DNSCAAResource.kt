package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add

class DNSCAAResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val flags: UByte,        // Flags (critical bit)
    private val tag: String,         // Property tag
    private val value: String        // Property value
) : DNSResourceRecord(name, DNSRRType.CAA, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$flags $tag \"$value\""

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(flags.toByte())
        
        // Add tag string
        val tagBytes = tag.toByteArray()
        rdataList.add(tagBytes.size.toByte())
        rdataList.addAll(tagBytes.toList())
        
        // Add value string (not length-prefixed)
        val valueBytes = value.toByteArray()
        rdataList.addAll(valueBytes.toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.CAA

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSCAAResource, Int> {
            var i = offset
            
            val flags = message[i].toUByte()
            i++
            
            // Parse tag string
            val tagLength = message[i].toInt() and 0xFF
            i++
            val tag = String(message.sliceArray(i until i + tagLength))
            i += tagLength
            
            // Parse value string (rest of the record)
            val valueLength = rdlength - 1 - 1 - tagLength
            val value = String(message.sliceArray(i until i + valueLength))
            i += valueLength
            
            return Pair(DNSCAAResource(name, dnsClass, ttl, flags, tag, value), i)
        }
    }
}