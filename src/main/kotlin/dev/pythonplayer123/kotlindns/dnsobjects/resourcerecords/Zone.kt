package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.builders.ZoneRule
import dev.pythonplayer123.kotlindns.dnsobjects.DNSQuestion

class Zone(
    var domain: String,
    private var records: Map<String, MutableList<DNSResourceRecord>>,
    private var rules: List<ZoneRule>
) {
    val authorities: List<DNSResourceRecord>
        get() = records.values.flatten().filter { record ->
            record.type == DNSRRType.NS
        }

    fun query(asked: DNSQuestion): List<DNSResourceRecord> {
        val ruleRecords: MutableList<DNSResourceRecord> = mutableListOf()
        for ((regex, handlers) in rules) {
            val match = regex.find(asked.qname) ?: continue
            for (handler in handlers)
                ruleRecords += handler(match, asked)
        }

        val ourRecords = records[asked.qname] ?: return ruleRecords

        return (ruleRecords + ourRecords.filter { record ->
            record.dnsClass == asked.qclass &&
                    record.name == asked.qname &&
                    record.type == asked.qtype
        })
    }
}
