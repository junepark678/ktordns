package dev.pythonplayer123.kotlindns.builders

import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSResourceRecord

@ZoneBuilderDsl
class RecordBuilder(private val zoneName: String, private var baseTTL: UInt) {
    private val records = mutableMapOf<String, MutableList<DNSResourceRecord>>()

    fun build(): Map<String, MutableList<DNSResourceRecord>> {
        return records
    }

    @RRBuilderDsl
    fun a(setup: ARecordBuilder.() -> Unit = {}) {
        val recordBuilder = ARecordBuilder(zoneName, baseTTL)
        recordBuilder.setup()
        val record = recordBuilder.build()
        if (records[record.name] == null) {
            records[record.name] = mutableListOf()
        }
        records[record.name]?.add(record)
    }
    @RRBuilderDsl
    fun cname(setup: CNAMERecordBuilder.() -> Unit = {}) {
        val recordBuilder = CNAMERecordBuilder(zoneName, baseTTL)
        recordBuilder.setup()
        val record = recordBuilder.build()
        if (records[record.name] == null) {
            records[record.name] = mutableListOf()
        }
        records[record.name]?.add(record)
    }
    @RRBuilderDsl
    fun ns(setup: NSRecordBuilder.() -> Unit = {}) {
        val recordBuilder = NSRecordBuilder(zoneName, baseTTL)
        recordBuilder.setup()
        val record = recordBuilder.build()
        if (records[record.name] == null) {
            records[record.name] = mutableListOf()
        }
        records[record.name]?.add(record)
    }
    @RRBuilderDsl
    fun aaaa(setup: AAAARecordBuilder.() -> Unit = {}) {
        val recordBuilder = AAAARecordBuilder(zoneName, baseTTL)
        recordBuilder.setup()
        val record = recordBuilder.build()
        if (records[record.name] == null) {
            records[record.name] = mutableListOf()
        }
        records[record.name]?.add(record)
    }
}
