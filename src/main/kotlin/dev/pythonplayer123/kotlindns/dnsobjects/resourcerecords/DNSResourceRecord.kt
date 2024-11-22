package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.dnsobjects.DNSQuestion
import dev.pythonplayer123.kotlindns.utils.*
import io.ktor.util.reflect.*
import kotlin.reflect.KClass
import kotlin.reflect.full.*

abstract class DNSResourceRecord(var name: String, var type: DNSRRType, var dnsClass: DNSQueryClass, var ttl: UInt) {
    val rdlength: UShort
        get() = rddata.size.toUShort()
    abstract val rddata: ByteArray
    abstract val rdTextualRepresentation: String

    override fun toString(): String {
        return rdTextualRepresentation
    }

    companion object {
        val value: DNSRRType = DNSRRType.UNKNOWN

        private fun parse(message: ByteArray, offset: Int): Pair<DNSResourceRecord, Int> {
            var (qname, i) = message.decompressName(offset)

            val qtype = DNSRRType.fromValue(message.readShort(i))
            i += 2
            if (qtype == DNSRRType.OPT) {
                i += 2 // class (payload size)
                i += 4 // TTL (extended RCODE)
                val rdlength = message.readShort(i).toShort()
                i += 2 // RDLEN
                i += rdlength
                return Pair(object: DNSResourceRecord(qname, qtype, DNSQueryClass.NONE, 0u) {
                    override val rddata: ByteArray
                        get() = message.sliceArray(i-10..i-rdlength)
                    override val rdTextualRepresentation: String
                        get() = rddata.toString()
                }, i)
            }
            val qclass = DNSQueryClass.fromValue(message.readShort(i))
            i += 2
            val ttl = message.readInt(i)
            i += 4
            val rdlength = message.readShort(i).toInt()
            i += 2

            val clazz = qtype.dnsResourceRecordClass!!
            @Suppress("UNCHECKED_CAST") val pairrrrr: Pair<DNSResourceRecord, Int> =
                (clazz.companionObject as KClass<DNSResourceCompanionObject>).objectInstance?.parse(
                    qname,
                    qclass,
                    ttl,
                    message,
                    i,
                    rdlength
                ) as Pair<DNSResourceRecord, Int>
            return pairrrrr
        }

        fun parseMany(message: ByteArray, offset: Int, count: Int): Pair<List<DNSResourceRecord>, Int> {
            val answers = mutableListOf<DNSResourceRecord>()

            var answerOffset = offset

            for (i in 0 until count) {
                println("answerOffset: $answerOffset")
                val (dnsRR, answerLen) = parse(message, answerOffset)
                answers.add(dnsRR)
                answerOffset = answerLen
            }
            return Pair(answers, answerOffset)
        }
    }

    open fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val headerMessage = compressor.compressName(name, message).toMutableList()
        headerMessage.add(type)
        headerMessage.add(dnsClass)
        headerMessage.add(ttl)
        headerMessage.add(rdlength)
        headerMessage.addAll(rddata.toList())
        return headerMessage.toByteArray()
    }
}
