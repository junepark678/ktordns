package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSRPResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val mboxDname: String,  // Mailbox domain name
    private val txtDname: String    // Text domain name
) : DNSResourceRecord(name, DNSRRType.RP, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$mboxDname $txtDname"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.addAll(compressor.compressName(mboxDname, message).toList())
        rdataList.addAll(compressor.compressName(txtDname, message).toList())
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.RP

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSRPResource, Int> {
            var i = offset
            val (mboxDname, mboxEnd) = message.decompressName(i)
            i = mboxEnd
            val (txtDname, txtEnd) = message.decompressName(i)
            i = txtEnd
            
            return Pair(DNSRPResource(name, dnsClass, ttl, mboxDname, txtDname), i)
        }
    }
}