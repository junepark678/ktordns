package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSKEYResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val flags: UShort,       // Flags
    private val protocol: UByte,     // Protocol
    private val algorithm: UByte,    // Algorithm
    private val publicKey: ByteArray // Public key
) : DNSResourceRecord(name, DNSRRType.KEY, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$flags $protocol $algorithm ${publicKey.joinToString("") { "%02x".format(it) }}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(flags)
        rdataList.add(protocol.toByte())
        rdataList.add(algorithm.toByte())
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
        override val value: DNSRRType = DNSRRType.KEY

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSKEYResource, Int> {
            var i = offset
            val flags = message.readShort(i)
            i += 2
            val protocol = message[i].toUByte()
            i++
            val algorithm = message[i].toUByte()
            i++
            
            // Rest is public key
            val keyLength = rdlength - 4
            val publicKey = message.sliceArray(i until i + keyLength)
            i += keyLength
            
            return Pair(DNSKEYResource(name, dnsClass, ttl, flags, protocol, algorithm, publicKey), i)
        }
    }
}