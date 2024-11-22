package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import java.net.Inet4Address

class DNSAResource(name: String, dnsClass: DNSQueryClass, ttl: UInt, var ipAddress: Inet4Address) : DNSResourceRecord(
    name, DNSRRType.A, dnsClass, ttl
) {
    override val rddata: ByteArray
        get() = ipAddress.address

    override val rdTextualRepresentation: String
        get() = ipAddress.hostAddress

    companion object : DNSResourceCompanionObject {
        override val value: DNSRRType = DNSRRType.A

        @Suppress("unused")
        override fun parse(
            name: String, dnsClass: DNSQueryClass, ttl: UInt, message: ByteArray, offset: Int, rdlength: Int
        ): Pair<DNSAResource, Int> {
            val ipAddress = Inet4Address.getByAddress(message.copyOfRange(offset, offset + 4))
            if (ipAddress !is Inet4Address) {
                throw IllegalArgumentException("Not an Inet6Address")
            }
            return Pair(DNSAResource(name, dnsClass, ttl, ipAddress), offset + 4)
        }
    }
}
