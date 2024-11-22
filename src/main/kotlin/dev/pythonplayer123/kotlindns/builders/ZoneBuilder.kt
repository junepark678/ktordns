package dev.pythonplayer123.kotlindns.builders

import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSResourceRecord
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.Zone

@ZoneBuilderDsl
class ZoneBuilder {
    private var records = mapOf<String, MutableList<DNSResourceRecord>>()

    @ZoneBuilderDsl
    var domain: String = "."

    @ZoneBuilderDsl
    var baseTTL = 60u

    private var rules = mutableListOf<ZoneRule>()

    @ZoneBuilderDsl
    fun rule(setup: ZoneRuleBuilder.() -> Unit = {}) {
        val ruleBuilder = ZoneRuleBuilder()
        ruleBuilder.setup()
        rules += ruleBuilder.build() ?: return
    }

    fun build(): Zone {
        return Zone(domain, records, rules)
    }

    @ZoneBuilderDsl
    fun records(setup: RecordBuilder.() -> Unit = {}) {
        val recordBuilder = RecordBuilder(domain, baseTTL)
        recordBuilder.setup()
        val record = recordBuilder.build()
        records = record
    }
}


