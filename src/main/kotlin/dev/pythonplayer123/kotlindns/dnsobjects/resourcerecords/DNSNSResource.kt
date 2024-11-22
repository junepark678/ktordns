package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.toDNSLabel

class DNSNSResource(name: String, dnsClass: DNSQueryClass, ttl: UInt, private val nsdname: String) :
    DNSResourceRecord(name, DNSRRType.NS, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = nsdname

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val messagem = message.toMutableList()
        val len = message.size
        messagem += compressor.compressName(name, message).toMutableList()
        rddata = messagem.toByteArray()
        messagem.add(type)
        messagem.add(dnsClass)
        messagem.add(ttl)
        rddata = compressor.compressName(nsdname, messagem.toByteArray())
        messagem.add(rdlength)
        messagem.addAll(rddata.toList())
        return messagem.toByteArray().sliceArray(len..<messagem.size)
    }

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.NS

        @Suppress("unused")
        override fun parse(
            name: String, dnsClass: DNSQueryClass, ttl: UInt, message: ByteArray, offset: Int, rdlength: Int
        ): Pair<DNSNSResource, Int> {
            val (nsdname, offsetnew) = message.decompressName(offset)
            return Pair(DNSNSResource(name, dnsClass, ttl, nsdname), offsetnew)
        }
    }
}
