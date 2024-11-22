package dev.pythonplayer123.kotlindns.builders

import com.google.common.net.InetAddresses
import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSAAAAResource
import java.net.Inet6Address

@RRBuilderDsl
class AAAARecordBuilder(zoneName: String, ttl: UInt): BaseRR(zoneName, ttl) {
    @RRBuilderDsl
    var ipAddress: String? = null

    fun build(): DNSAAAAResource {
        if (ipAddress == null) {
            throw IllegalArgumentException("ipAddress is required")
        }
        val address = InetAddresses.forString(ipAddress!!)
        if (address !is Inet6Address) {
            throw IllegalArgumentException("ipAddress must be Inet4Address")
        }
        return DNSAAAAResource(fullZone, DNSQueryClass.IN, ttl, address)
    }
}
