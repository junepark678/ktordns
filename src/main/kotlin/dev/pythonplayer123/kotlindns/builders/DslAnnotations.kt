package dev.pythonplayer123.kotlindns.builders

import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.Zone

@DslMarker
annotation class RRBuilderDsl

@DslMarker
annotation class ZoneBuilderDsl

@ZoneBuilderDsl
fun zone(setup: ZoneBuilder.() -> Unit): Zone {
    val zoneBuilder = ZoneBuilder()
    zoneBuilder.setup()
    return zoneBuilder.build()
}
