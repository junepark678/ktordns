package dev.pythonplayer123.kotlindns.dnsobjects

import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSRRType
import dev.pythonplayer123.kotlindns.utils.*

class DNSQuestion(var qname: String, var qtype: DNSRRType, var qclass: DNSQueryClass) {
    companion object {
        private fun parse(message: ByteArray, offset: Int): Pair<DNSQuestion, Int> {
            var (qname, i) = message.decompressName(offset)

            val qtype = DNSRRType.fromValue(message.readShort(i))
            i += 2
            val qclass = DNSQueryClass.fromValue(message.readShort(i))

            i += 2

            return Pair(DNSQuestion(qname, qtype, qclass), i)
        }

        fun parseMany(message: ByteArray, offset: Int, count: Int): Pair<List<DNSQuestion>, Int> {
            val questions = mutableListOf<DNSQuestion>()

            var questionOffset = offset

            for (i in 0 until count) {
                val (dnsQuestion, questionLen) = parse(message, questionOffset)
                questions.add(dnsQuestion)
                questionOffset = questionLen
            }
            return Pair(questions, questionOffset)
        }
    }

    fun toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
        val encodedQname = compressor.compressName(qname, message).toMutableList()
        encodedQname.add(qtype)
        encodedQname.add(qclass)
        return encodedQname.toByteArray()
    }
}
