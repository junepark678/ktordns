package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readInt
import dev.pythonplayer123.kotlindns.utils.readShort
import dev.pythonplayer123.kotlindns.utils.toDNSLabel

/**
 * DNS RRSIG (Resource Record Signature) Resource Record for DNSSEC
 * RFC 4034
 */
class DNSRRSIGResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val typeCovered: UShort,        // Type covered
    private val algorithm: UByte,           // Algorithm
    private val labels: UByte,              // Labels
    private val originalTTL: UInt,          // Original TTL
    private val signatureExpiration: UInt,  // Signature expiration
    private val signatureInception: UInt,   // Signature inception
    private val keyTag: UShort,             // Key tag
    private val signerName: String,         // Signer's name
    private val signature: ByteArray        // Signature
) : DNSResourceRecord(name, DNSRRType.RRSIG, dnsClass, ttl) {
    
    override val rddata: ByteArray
        get() {
            val rdataList = mutableListOf<Byte>()
            rdataList.add(typeCovered)
            rdataList.add(algorithm.toByte())
            rdataList.add(labels.toByte())
            rdataList.add(originalTTL)
            rdataList.add(signatureExpiration)
            rdataList.add(signatureInception)
            rdataList.add(keyTag)
            rdataList.addAll(signerName.toDNSLabel().toList())
            rdataList.addAll(signature.toList())
            return rdataList.toByteArray()
        }

    override val rdTextualRepresentation: String
        get() = "$typeCovered $algorithm $labels $originalTTL $signatureExpiration $signatureInception $keyTag $signerName ${java.util.Base64.getEncoder().encodeToString(signature)}"

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.RRSIG

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSRRSIGResource, Int> {
            var i = offset
            val typeCovered = message.readShort(i)
            i += 2
            val algorithm = message[i].toUByte()
            i++
            val labels = message[i].toUByte()
            i++
            val originalTTL = message.readInt(i)
            i += 4
            val signatureExpiration = message.readInt(i)
            i += 4
            val signatureInception = message.readInt(i)
            i += 4
            val keyTag = message.readShort(i)
            i += 2
            val (signerName, signerNameEnd) = message.decompressName(i)
            i = signerNameEnd
            
            val signatureLength = rdlength - (i - offset)
            val signature = if (signatureLength > 0) {
                message.sliceArray(i until i + signatureLength)
            } else {
                byteArrayOf()
            }
            
            return Pair(
                DNSRRSIGResource(name, dnsClass, ttl, typeCovered, algorithm, labels, originalTTL, signatureExpiration, signatureInception, keyTag, signerName, signature),
                offset + rdlength
            )
        }
    }
}