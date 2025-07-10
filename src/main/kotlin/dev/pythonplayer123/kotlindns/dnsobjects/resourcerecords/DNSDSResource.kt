package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readShort

/**
 * DNS DS (Delegation Signer) Resource Record for DNSSEC
 * RFC 4034
 */
class DNSDSResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val keyTag: UShort,         // Key tag
    private val algorithm: UByte,       // Algorithm
    private val digestType: UByte,      // Digest type
    private val digest: ByteArray       // Digest
) : DNSResourceRecord(name, DNSRRType.DS, dnsClass, ttl) {
    
    override val rddata: ByteArray
        get() {
            val rdataList = mutableListOf<Byte>()
            rdataList.add(keyTag)
            rdataList.add(algorithm.toByte())
            rdataList.add(digestType.toByte())
            rdataList.addAll(digest.toList())
            return rdataList.toByteArray()
        }

    override val rdTextualRepresentation: String
        get() = "$keyTag $algorithm $digestType ${java.util.Base64.getEncoder().encodeToString(digest)}"

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.DS

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSDSResource, Int> {
            var i = offset
            val keyTag = message.readShort(i)
            i += 2
            val algorithm = message[i].toUByte()
            i++
            val digestType = message[i].toUByte()
            i++
            val digestLength = rdlength - 4
            val digest = if (digestLength > 0) {
                message.sliceArray(i until i + digestLength)
            } else {
                byteArrayOf()
            }
            
            return Pair(
                DNSDSResource(name, dnsClass, ttl, keyTag, algorithm, digestType, digest),
                offset + rdlength
            )
        }
    }
}