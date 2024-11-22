package dev.pythonplayer123.kotlindns.builders

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSNSResource

@RRBuilderDsl
class NSRecordBuilder(private val zoneName: String, ttl: UInt): BaseRR(zoneName, ttl) {
    @RRBuilderDsl
    var server: String? = null

    fun build(): DNSNSResource {
        if (server != null) {
            return DNSNSResource(fullZone, DNSQueryClass.IN, ttl, server!!)
        }
        throw IllegalArgumentException("No server definition found for $zoneName")
    }
}
