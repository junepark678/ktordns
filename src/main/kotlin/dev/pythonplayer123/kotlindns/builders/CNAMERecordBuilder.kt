package dev.pythonplayer123.kotlindns.builders

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSCNAMEResource

@RRBuilderDsl
class CNAMERecordBuilder(zoneName: String, ttl: UInt): BaseRR(zoneName, ttl) {
    @RRBuilderDsl
    var cname: String? = null

    fun build(): DNSCNAMEResource {
        if (cname == null) {
            throw IllegalArgumentException("cname is required")
        }
        return DNSCNAMEResource(fullZone, DNSQueryClass.IN, ttl, cname!!)
    }
}
