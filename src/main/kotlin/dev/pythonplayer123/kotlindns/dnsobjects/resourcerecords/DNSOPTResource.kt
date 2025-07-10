package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readShort

/**
 * DNS OPT Resource Record for EDNS (Extension Mechanisms for DNS)
 * RFC 6891
 */
class DNSOPTResource(
    name: String,
    private val payloadSize: UShort,      // UDP payload size (replaces class field)
    private val extendedRcode: UByte,     // Extended RCODE (high 8 bits of extended 12-bit RCODE)
    private val version: UByte,           // EDNS version
    private val dnssecOK: Boolean,        // DNSSEC OK bit
    private val options: List<EDNSOption> = listOf()  // EDNS options
) : DNSResourceRecord(name, DNSRRType.OPT, DNSQueryClass.NONE, 0u) {
    
    override val rddata: ByteArray
        get() {
            val rdataList = mutableListOf<Byte>()
            for (option in options) {
                rdataList.add(option.code)
                rdataList.add(option.length)
                rdataList.addAll(option.data.toList())
            }
            return rdataList.toByteArray()
        }

    override val rdTextualRepresentation: String
        get() = "EDNS: version=$version, payload=$payloadSize, rcode=$extendedRcode, dnssec=$dnssecOK, options=${options.size}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        headerMessage.add(type)
        headerMessage.add(payloadSize)  // UDP payload size (replaces class)
        
        // TTL field contains EDNS flags
        var ttlValue = 0u
        ttlValue = ttlValue or (extendedRcode.toUInt() shl 24)  // Extended RCODE
        ttlValue = ttlValue or (version.toUInt() shl 16)        // Version
        if (dnssecOK) {
            ttlValue = ttlValue or (1u shl 15)                  // DO bit
        }
        headerMessage.add(ttlValue)
        
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.OPT

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSOPTResource, Int> {
            // For OPT records, the class field contains the UDP payload size
            val payloadSize = dnsClass.value
            
            // Extract EDNS fields from TTL
            val extendedRcode = ((ttl shr 24) and 0xFFu).toUByte()
            val version = ((ttl shr 16) and 0xFFu).toUByte()
            val dnssecOK = ((ttl shr 15) and 1u) == 1u
            
            // Parse options
            val options = mutableListOf<EDNSOption>()
            var i = offset
            val endOffset = offset + rdlength
            
            while (i < endOffset - 4) {
                val optionCode = message.readShort(i)
                i += 2
                val optionLength = message.readShort(i)
                i += 2
                val optionData = if (optionLength > 0u && i + optionLength.toInt() <= endOffset) {
                    message.sliceArray(i until i + optionLength.toInt())
                } else {
                    byteArrayOf()
                }
                if (optionLength > 0u) {
                    i += optionLength.toInt()
                }
                options.add(EDNSOption(optionCode, optionLength, optionData))
            }
            
            return Pair(
                DNSOPTResource(name, payloadSize, extendedRcode, version, dnssecOK, options), 
                endOffset
            )
        }
    }
}

/**
 * EDNS Option
 */
data class EDNSOption(
    val code: UShort,
    val length: UShort,
    val data: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EDNSOption

        if (code != other.code) return false
        if (length != other.length) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = code.hashCode()
        result = 31 * result + length.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}