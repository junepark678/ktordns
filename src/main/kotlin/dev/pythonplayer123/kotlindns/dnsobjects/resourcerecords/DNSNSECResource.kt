package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.toDNSLabel

/**
 * DNS NSEC (Next Secure) Resource Record for DNSSEC
 * RFC 4034
 */
class DNSNSECResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val nextDomainName: String,     // Next domain name
    private val typeBitMaps: ByteArray      // Type bit maps
) : DNSResourceRecord(name, DNSRRType.NSEC, dnsClass, ttl) {
    
    override val rddata: ByteArray
        get() {
            val rdataList = mutableListOf<Byte>()
            rdataList.addAll(nextDomainName.toDNSLabel().toList())
            rdataList.addAll(typeBitMaps.toList())
            return rdataList.toByteArray()
        }

    override val rdTextualRepresentation: String
        get() = "$nextDomainName ${typeBitMaps.joinToString(" ") { "%02x".format(it) }}"

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.NSEC

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSNSECResource, Int> {
            var i = offset
            val (nextDomainName, nextDomainEnd) = message.decompressName(i)
            i = nextDomainEnd
            
            val typeBitMapsLength = rdlength - (i - offset)
            val typeBitMaps = if (typeBitMapsLength > 0) {
                message.sliceArray(i until i + typeBitMapsLength)
            } else {
                byteArrayOf()
            }
            
            return Pair(
                DNSNSECResource(name, dnsClass, ttl, nextDomainName, typeBitMaps),
                offset + rdlength
            )
        }
    }
}