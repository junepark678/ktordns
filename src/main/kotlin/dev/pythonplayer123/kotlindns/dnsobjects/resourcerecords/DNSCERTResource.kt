package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSCERTResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val certType: UShort,      // Certificate type
    private val keyTag: UShort,        // Key tag
    private val algorithm: UByte,      // Algorithm
    private val certificate: ByteArray // Certificate data
) : DNSResourceRecord(name, DNSRRType.CERT, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$certType $keyTag $algorithm ${certificate.joinToString("") { "%02x".format(it) }}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(certType)
        rdataList.add(keyTag)
        rdataList.add(algorithm.toByte())
        rdataList.addAll(certificate.toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.CERT

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSCERTResource, Int> {
            var i = offset
            
            val certType = message.readShort(i)
            i += 2
            val keyTag = message.readShort(i)
            i += 2
            val algorithm = message[i].toUByte()
            i++
            
            // Parse certificate data (rest of the record)
            val certLength = rdlength - 5
            val certificate = message.sliceArray(i until i + certLength)
            i += certLength
            
            return Pair(DNSCERTResource(name, dnsClass, ttl, certType, keyTag, algorithm, certificate), i)
        }
    }
}