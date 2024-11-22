package dev.pythonplayer123.kotlindns.builders

import com.google.common.net.InetAddresses
import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSAResource
import java.net.Inet4Address

@RRBuilderDsl
class ARecordBuilder(zoneName: String, ttl: UInt): BaseRR(zoneName, ttl) {
    @RRBuilderDsl
    var ipAddress: String? = null

    fun build(): DNSAResource {
        if (ipAddress == null) {
            throw IllegalArgumentException("ipAddress is required")
        }
        val address = InetAddresses.forString(ipAddress!!)
        if (address !is Inet4Address) {
            throw IllegalArgumentException("ipAddress must be Inet4Address")
        }
        return DNSAResource(fullZone, DNSQueryClass.IN, ttl, address)
    }
}
