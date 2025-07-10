package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add

class DNSHINFOResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val cpu: String,  // CPU type
    private val os: String    // Operating system
) : DNSResourceRecord(name, DNSRRType.HINFO, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "\"$cpu\" \"$os\""

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA - each string is prefixed with its length
        val rdataList = mutableListOf<Byte>()
        val cpuBytes = cpu.toByteArray()
        val osBytes = os.toByteArray()
        
        rdataList.add(cpuBytes.size.toByte())
        rdataList.addAll(cpuBytes.toList())
        rdataList.add(osBytes.size.toByte())
        rdataList.addAll(osBytes.toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.HINFO

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSHINFOResource, Int> {
            var i = offset
            
            // Parse CPU string
            val cpuLength = message[i].toInt() and 0xFF
            i++
            val cpu = String(message.sliceArray(i until i + cpuLength))
            i += cpuLength
            
            // Parse OS string
            val osLength = message[i].toInt() and 0xFF
            i++
            val os = String(message.sliceArray(i until i + osLength))
            i += osLength
            
            return Pair(DNSHINFOResource(name, dnsClass, ttl, cpu, os), i)
        }
    }
}