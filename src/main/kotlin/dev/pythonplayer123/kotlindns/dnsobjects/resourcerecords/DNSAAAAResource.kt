package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import java.net.Inet6Address

class DNSAAAAResource(name: String, dnsClass: DNSQueryClass, ttl: UInt, var ipAddress: Inet6Address) : DNSResourceRecord(
    name, DNSRRType.AAAA, dnsClass, ttl
) {
    override val rddata: ByteArray
        get() = ipAddress.address

    override val rdTextualRepresentation: String
        get() = ipAddress.hostAddress

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.AAAA

        @Suppress("unused")
        override fun parse(
            name: String, dnsClass: DNSQueryClass, ttl: UInt, message: ByteArray, offset: Int, rdlength: Int
        ): Pair<DNSAAAAResource, Int> {
            val ipAddress = Inet6Address.getByAddress(message.copyOfRange(offset, offset + 16))
            if (ipAddress !is Inet6Address) {
                throw IllegalArgumentException("Not an Inet6Address")
            }
            return Pair(DNSAAAAResource(name, dnsClass, ttl, ipAddress), offset + 16)
        }
    }
}
