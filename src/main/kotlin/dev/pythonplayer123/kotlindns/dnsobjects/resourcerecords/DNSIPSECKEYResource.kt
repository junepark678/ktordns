package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSIPSECKEYResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val precedence: UByte,    // Precedence
    private val gatewayType: UByte,   // Gateway type
    private val algorithm: UByte,     // Algorithm
    private val gateway: ByteArray,   // Gateway
    private val publicKey: ByteArray  // Public key
) : DNSResourceRecord(name, DNSRRType.IPSECKEY, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$precedence $gatewayType $algorithm ${gateway.joinToString("") { "%02x".format(it) }} ${publicKey.joinToString("") { "%02x".format(it) }}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(precedence.toByte())
        rdataList.add(gatewayType.toByte())
        rdataList.add(algorithm.toByte())
        rdataList.addAll(gateway.toList())
        rdataList.addAll(publicKey.toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.IPSECKEY

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSIPSECKEYResource, Int> {
            var i = offset
            val precedence = message[i].toUByte()
            i++
            val gatewayType = message[i].toUByte()
            i++
            val algorithm = message[i].toUByte()
            i++
            
            // Gateway length depends on type
            val gatewayLength = when (gatewayType.toInt()) {
                0 -> 0     // No gateway
                1 -> 4     // IPv4
                2 -> 16    // IPv6
                3 -> {     // Domain name - variable length
                    val (_, end) = message.decompressName(i)
                    end - i
                }
                else -> 0
            }
            
            val gateway = message.sliceArray(i until i + gatewayLength)
            i += gatewayLength
            
            // Rest is public key
            val keyLength = rdlength - 3 - gatewayLength
            val publicKey = message.sliceArray(i until i + keyLength)
            i += keyLength
            
            return Pair(DNSIPSECKEYResource(name, dnsClass, ttl, precedence, gatewayType, algorithm, gateway, publicKey), i)
        }
    }
}