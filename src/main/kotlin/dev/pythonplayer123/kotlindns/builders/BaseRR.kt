package dev.pythonplayer123.kotlindns.builders



abstract class BaseRR(private val zoneName: String, @property:RRBuilderDsl var ttl: UInt) {
    @RRBuilderDsl
    var domain: String = ""

    protected val fullZone: String
        get() = if (domain.isNotEmpty()) "${domain}.${zoneName}" else zoneName

}

