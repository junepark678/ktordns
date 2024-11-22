package dev.pythonplayer123.kotlindns.builders

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQuestion
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSResourceRecord

typealias ZoneHandler = (MatchResult, DNSQuestion) -> List<DNSResourceRecord>
typealias ZoneRule = Pair<Regex, List<ZoneHandler>>

@ZoneBuilderDsl
class ZoneRuleBuilder {
    @ZoneBuilderDsl
    var regex: Regex? = null

    private val handlers: MutableList<ZoneHandler> = mutableListOf()

    @ZoneBuilderDsl
    fun handler(theHandler: ZoneHandler) {
        handlers.add(theHandler)
    }


    fun build(): ZoneRule? {
        if (regex == null || handlers.isEmpty())
            return null

        return ZoneRule(regex!!, handlers)
    }
}
