package dev.pythonplayer123.kotlindns.dnsobjects

import dev.pythonplayer123.kotlindns.utils.readShort
import dev.pythonplayer123.kotlindns.utils.toBytes

class DNSHeader(
    var id: UShort,
    var flags: DNSHeaderFlags,
    var questionCount: UShort,
    var answerCount: UShort,
    var authorityRRCount: UShort,
    var additionalRRCount: UShort
) {
    companion object {
        fun parse(data: ByteArray): DNSHeader {
            val id = data.readShort(0)
            val flagArray = byteArrayOf(data[2], data[3])
            val flags = DNSHeaderFlags.parse(flagArray)
            val questionCount = data.readShort(4)
            val answerCount = data.readShort(6)
            val authorityRRCount = data.readShort(8)
            val additionalRRCount = data.readShort(10)

            return DNSHeader(id, flags, questionCount, answerCount, authorityRRCount, additionalRRCount)
        }
    }

    fun toByteArray(): ByteArray {
        return id.toBytes() + flags.toByteArray() + questionCount.toBytes() + answerCount.toBytes() + authorityRRCount.toBytes() + additionalRRCount.toBytes()
    }
}
