package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readInt

class DNSSOAResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val mname: String,      // Primary name server
    private val rname: String,      // Email of responsible person
    private val serial: UInt,       // Serial number
    private val refresh: UInt,      // Refresh interval
    private val retry: UInt,        // Retry interval
    private val expire: UInt,       // Expire time
    private val minimum: UInt       // Minimum TTL
) : DNSResourceRecord(name, DNSRRType.SOA, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$mname $rname $serial $refresh $retry $expire $minimum"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.addAll(compressor.compressName(mname, message).toList())
        rdataList.addAll(compressor.compressName(rname, message).toList())
        rdataList.add(serial)
        rdataList.add(refresh)
        rdataList.add(retry)
        rdataList.add(expire)
        rdataList.add(minimum)
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.SOA

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSSOAResource, Int> {
            var i = offset
            val (mname, mnameEnd) = message.decompressName(i)
            i = mnameEnd
            val (rname, rnameEnd) = message.decompressName(i)
            i = rnameEnd
            val serial = message.readInt(i)
            i += 4
            val refresh = message.readInt(i)
            i += 4
            val retry = message.readInt(i)
            i += 4
            val expire = message.readInt(i)
            i += 4
            val minimum = message.readInt(i)
            i += 4
            
            return Pair(DNSSOAResource(name, dnsClass, ttl, mname, rname, serial, refresh, retry, expire, minimum), i)
        }
    }
}