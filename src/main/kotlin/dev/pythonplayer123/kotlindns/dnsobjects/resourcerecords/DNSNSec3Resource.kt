package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSNSEC3Resource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val hashAlgorithm: UByte,    // Hash algorithm
    private val flags: UByte,            // Flags
    private val iterations: UShort,      // Iterations
    private val saltLength: UByte,       // Salt length
    private val salt: ByteArray,         // Salt
    private val hashLength: UByte,       // Hash length
    private val nextHashedOwnerName: ByteArray,  // Next hashed owner name
    private val typeBitMaps: ByteArray   // Type bit maps
) : DNSResourceRecord(name, DNSRRType.NSEC3, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$hashAlgorithm $flags $iterations ${salt.joinToString("") { "%02x".format(it) }} ${nextHashedOwnerName.joinToString("") { "%02x".format(it) }}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(hashAlgorithm.toByte())
        rdataList.add(flags.toByte())
        rdataList.add(iterations)
        rdataList.add(saltLength.toByte())
        rdataList.addAll(salt.toList())
        rdataList.add(hashLength.toByte())
        rdataList.addAll(nextHashedOwnerName.toList())
        rdataList.addAll(typeBitMaps.toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.NSEC3

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSNSEC3Resource, Int> {
            var i = offset
            val hashAlgorithm = message[i].toUByte()
            i++
            val flags = message[i].toUByte()
            i++
            val iterations = message.readShort(i)
            i += 2
            val saltLength = message[i].toUByte()
            i++
            val salt = message.sliceArray(i until i + saltLength.toInt())
            i += saltLength.toInt()
            val hashLength = message[i].toUByte()
            i++
            val nextHashedOwnerName = message.sliceArray(i until i + hashLength.toInt())
            i += hashLength.toInt()
            
            // Rest is type bit maps
            val typeBitMapsLength = rdlength - 4 - 1 - saltLength.toInt() - 1 - hashLength.toInt()
            val typeBitMaps = message.sliceArray(i until i + typeBitMapsLength)
            i += typeBitMapsLength
            
            return Pair(DNSNSEC3Resource(name, dnsClass, ttl, hashAlgorithm, flags, iterations, saltLength, salt, hashLength, nextHashedOwnerName, typeBitMaps), i)
        }
    }
}