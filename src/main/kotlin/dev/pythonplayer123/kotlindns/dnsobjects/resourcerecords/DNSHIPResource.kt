package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.add
import dev.pythonplayer123.kotlindns.utils.decompressName
import dev.pythonplayer123.kotlindns.utils.readShort

class DNSHIPResource(
    name: String,
    dnsClass: DNSQueryClass,
    ttl: UInt,
    private val hitLength: UByte,         // HIT length
    private val pkAlgorithm: UByte,       // PK algorithm
    private val pkLength: UShort,         // PK length
    private val hit: ByteArray,           // Host Identity Tag
    private val publicKey: ByteArray,     // Public key
    private val rendezvousServers: List<String>  // Rendezvous servers
) : DNSResourceRecord(name, DNSRRType.HIP, dnsClass, ttl) {
    override lateinit var rddata: ByteArray

    override val rdTextualRepresentation: String
        get() = "$hitLength $pkAlgorithm $pkLength ${hit.joinToString("") { "%02x".format(it) }} ${publicKey.joinToString("") { "%02x".format(it) }} ${rendezvousServers.joinToString(" ")}"

    override fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        
        // Build the RDATA
        val rdataList = mutableListOf<Byte>()
        rdataList.add(hitLength.toByte())
        rdataList.add(pkAlgorithm.toByte())
        rdataList.add(pkLength)
        rdataList.addAll(hit.toList())
        rdataList.addAll(publicKey.toList())
        
        // Add rendezvous servers
        for (server in rendezvousServers) {
            rdataList.addAll(compressor.compressName(server, message).toList())
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
        override val value: DNSRRType = DNSRRType.HIP

        override fun parse(
            name: String,
            dnsClass: DNSQueryClass,
            ttl: UInt,
            message: ByteArray,
            offset: Int,
            rdlength: Int
        ): Pair<DNSHIPResource, Int> {
            var i = offset
            val hitLength = message[i].toUByte()
            i++
            val pkAlgorithm = message[i].toUByte()
            i++
            val pkLength = message.readShort(i)
            i += 2
            
            val hit = message.sliceArray(i until i + hitLength.toInt())
            i += hitLength.toInt()
            
            val publicKey = message.sliceArray(i until i + pkLength.toInt())
            i += pkLength.toInt()
            
            // Parse rendezvous servers
            val rendezvousServers = mutableListOf<String>()
            val endOffset = offset + rdlength
            
            while (i < endOffset) {
                val (server, serverEnd) = message.decompressName(i)
                rendezvousServers.add(server)
                i = serverEnd
            }
            
            return Pair(DNSHIPResource(name, dnsClass, ttl, hitLength, pkAlgorithm, pkLength, hit, publicKey, rendezvousServers), i)
        }
    }
}