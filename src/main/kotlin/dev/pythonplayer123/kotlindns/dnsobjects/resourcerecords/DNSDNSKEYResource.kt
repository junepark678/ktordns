package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readShort

/**
 * DNS DNSKEY Resource Record for DNSSEC
 * RFC 4034
 */
class DNSDNSKEYResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val flags: UShort,          // Flags (bit 7 = Zone Key, bit 15 = Secure Entry Point)
    private val protocol: UByte,        // Protocol (must be 3)
    private val algorithm: UByte,       // Algorithm
    private val publicKey: ByteArray    // Public key
) : DNSResourceRecord(name, DNSRRType.DNSKEY, dnsClass, ttl) {
    
    override val rddata: ByteArray
        get() {
            val rdataList = mutableListOf<Byte>()
            rdataList.add(flags)
            rdataList.add(protocol.toByte())
            rdataList.add(algorithm.toByte())
            rdataList.addAll(publicKey.toList())
            return rdataList.toByteArray()
        }

    override val rdTextualRepresentation: String
        get() = "$flags $protocol $algorithm ${java.util.Base64.getEncoder().encodeToString(publicKey)}"

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.DNSKEY

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSDNSKEYResource, Int> {
            var i = offset
            val flags = message.readShort(i)
            i += 2
            val protocol = message[i].toUByte()
            i++
            val algorithm = message[i].toUByte()
            i++
            val publicKeyLength = rdlength - 4
            val publicKey = if (publicKeyLength > 0) {
                message.sliceArray(i until i + publicKeyLength)
            } else {
                byteArrayOf()
            }
            
            return Pair(
                DNSDNSKEYResource(name, dnsClass, ttl, flags, protocol, algorithm, publicKey),
                offset + rdlength
            )
        }
    }
}