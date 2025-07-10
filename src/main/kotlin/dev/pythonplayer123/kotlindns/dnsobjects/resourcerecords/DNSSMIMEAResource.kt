package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSSMIMEAResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val certUsage: UByte,        // Certificate usage
    private val selector: UByte,         // Selector
    private val matchingType: UByte,     // Matching type
    private val certAssocData: ByteArray // Certificate association data
) : DNSResourceRecord(name, DNSRRType.SMIMEA, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$certUsage $selector $matchingType ${certAssocData.joinToString("") { "%02x".format(it) }}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(certUsage.toByte())
        rdataList.add(selector.toByte())
        rdataList.add(matchingType.toByte())
        rdataList.addAll(certAssocData.toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.SMIMEA

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSSMIMEAResource, Int> {
            var i = offset
            
            val certUsage = message[i].toUByte()
            i++
            val selector = message[i].toUByte()
            i++
            val matchingType = message[i].toUByte()
            i++
            
            // Parse certificate association data (rest of the record)
            val dataLength = rdlength - 3
            val certAssocData = message.sliceArray(i until i + dataLength)
            i += dataLength
            
            return Pair(DNSSMIMEAResource(name, dnsClass, ttl, certUsage, selector, matchingType, certAssocData), i)
        }
    }
}