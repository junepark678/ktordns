package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add

class DNSTXTResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val txtData: List<String>  // List of text strings
) : DNSResourceRecord(name, DNSRRType.TXT, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = txtData.joinToString(" ") { "\"$it\"" }

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA - each string is prefixed with its length
        val rdataList = mutableListOf<Byte>()
        for (text in txtData) {
            val textBytes = text.toByteArray()
            rdataList.add(textBytes.size.toByte())
            rdataList.addAll(textBytes.toList())
        }
        
        rddata = rdataList.toByteArray()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.TXT

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSTXTResource, Int> {
            val txtStrings = mutableListOf<String>()
            var i = offset
            val endOffset = offset + rdlength
            
            while (i < endOffset) {
                val length = message[i].toInt() and 0xFF
                i++
                if (i + length <= endOffset) {
                    val text = String(message.sliceArray(i until i + length))
                    txtStrings.add(text)
                    i += length
                } else {
                    break
                }
            }
            
            return Pair(DNSTXTResource(name, dnsClass, ttl, txtStrings), endOffset)
        }
    }
}