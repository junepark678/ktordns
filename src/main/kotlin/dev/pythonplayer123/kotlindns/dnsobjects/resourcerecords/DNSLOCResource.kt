package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.readInt

class DNSLOCResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val version: UByte,      // Version (typically 0)
    private val size: UByte,         // Size
    private val hPrecision: UByte,   // Horizontal precision
    private val vPrecision: UByte,   // Vertical precision
    private val latitude: UInt,      // Latitude
    private val longitude: UInt,     // Longitude
    private val altitude: UInt       // Altitude
) : DNSResourceRecord(name, DNSRRType.LOC, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "LOC $version $size $hPrecision $vPrecision $latitude $longitude $altitude"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(version.toByte())
        rdataList.add(size.toByte())
        rdataList.add(hPrecision.toByte())
        rdataList.add(vPrecision.toByte())
        rdataList.add(latitude)
        rdataList.add(longitude)
        rdataList.add(altitude)
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.LOC

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSLOCResource, Int> {
            var i = offset
            
            val version = message[i].toUByte()
            i++
            val size = message[i].toUByte()
            i++
            val hPrecision = message[i].toUByte()
            i++
            val vPrecision = message[i].toUByte()
            i++
            val latitude = message.readInt(i)
            i += 4
            val longitude = message.readInt(i)
            i += 4
            val altitude = message.readInt(i)
            i += 4
            
            return Pair(DNSLOCResource(name, dnsClass, ttl, version, size, hPrecision, vPrecision, latitude, longitude, altitude), i)
        }
    }
}