package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSNAPTRResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val order: UShort,       // Order preference
    private val preference: UShort,  // Preference
    private val flags: String,       // Flags
    private val services: String,    // Services
    private val regexp: String,      // Regular expression
    private val replacement: String  // Replacement
) : DNSResourceRecord(name, DNSRRType.NAPTR, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$order $preference \"$flags\" \"$services\" \"$regexp\" $replacement"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(order)
        rdataList.add(preference)
        
        // Add flags string
        val flagsBytes = flags.toByteArray()
        rdataList.add(flagsBytes.size.toByte())
        rdataList.addAll(flagsBytes.toList())
        
        // Add services string
        val servicesBytes = services.toByteArray()
        rdataList.add(servicesBytes.size.toByte())
        rdataList.addAll(servicesBytes.toList())
        
        // Add regexp string
        val regexpBytes = regexp.toByteArray()
        rdataList.add(regexpBytes.size.toByte())
        rdataList.addAll(regexpBytes.toList())
        
        // Add replacement domain name
        rdataList.addAll(compressor.compressName(replacement, message).toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.NAPTR

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSNAPTRResource, Int> {
            var i = offset
            
            val order = message.readShort(i)
            i += 2
            val preference = message.readShort(i)
            i += 2
            
            // Parse flags string
            val flagsLength = message[i].toInt() and 0xFF
            i++
            val flags = String(message.sliceArray(i until i + flagsLength))
            i += flagsLength
            
            // Parse services string
            val servicesLength = message[i].toInt() and 0xFF
            i++
            val services = String(message.sliceArray(i until i + servicesLength))
            i += servicesLength
            
            // Parse regexp string
            val regexpLength = message[i].toInt() and 0xFF
            i++
            val regexp = String(message.sliceArray(i until i + regexpLength))
            i += regexpLength
            
            // Parse replacement domain name
            val (replacement, replacementEnd) = message.decompressName(i)
            i = replacementEnd
            
            return Pair(DNSNAPTRResource(name, dnsClass, ttl, order, preference, flags, services, regexp, replacement), i)
        }
    }
}