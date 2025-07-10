package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSSSHFPResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val algorithm: UByte,       // Algorithm
    private val fpType: UByte,          // Fingerprint type
    private val fingerprint: ByteArray  // Fingerprint
) : DNSResourceRecord(name, DNSRRType.SSHFP, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$algorithm $fpType ${fingerprint.joinToString("") { "%02x".format(it) }}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(algorithm.toByte())
        rdataList.add(fpType.toByte())
        rdataList.addAll(fingerprint.toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.SSHFP

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSSSHFPResource, Int> {
            var i = offset
            
            val algorithm = message[i].toUByte()
            i++
            val fpType = message[i].toUByte()
            i++
            
            // Parse fingerprint (rest of the record)
            val fpLength = rdlength - 2
            val fingerprint = message.sliceArray(i until i + fpLength)
            i += fpLength
            
            return Pair(DNSSSHFPResource(name, dnsClass, ttl, algorithm, fpType, fingerprint), i)
        }
    }
}