package dev.pythonplayer123.kotlindns.dnsobjects

import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSResourceRecord
import dev.pythonplayer123.kotlindns.utils.DNSCompressor
import dev.pythonplayer123.kotlindns.utils.toByteArray

class DNSPacket(
    var header: DNSHeader,
    var questions: List<DNSQuestion>,
    var answers: List<DNSResourceRecord>,
    var authorities: List<DNSResourceRecord>,
    var extra: List<DNSResourceRecord>
) {
    constructor(
        originalPacket: DNSPacket,
        answers: List<DNSResourceRecord>,
        authorities: List<DNSResourceRecord>,
        extra: List<DNSResourceRecord>
    ) : this(
        DNSHeader(
            originalPacket.header.id,
            originalPacket.header.flags.responseHeaders(),
            originalPacket.questions.size.toUShort(),
            answers.size.toUShort(),
            authorities.size.toUShort(),
            extra.size.toUShort()
        ), originalPacket.questions, answers, authorities, extra
    )

    companion object {
        @OptIn(ExperimentalStdlibApi::class)
        fun parse(packet: ByteArray): DNSPacket {
            println(packet.toHexString())
            val header = DNSHeader.parse(packet)
            val (questions, offset) = DNSQuestion.parseMany(packet, 12, header.questionCount.toInt())
            val (answers, offset2) = DNSResourceRecord.parseMany(packet, offset, header.answerCount.toInt())
            val (authoritites, offset3) = DNSResourceRecord.parseMany(packet, offset2, header.authorityRRCount.toInt())
            val (extra, _) = DNSResourceRecord.parseMany(packet, offset3, header.additionalRRCount.toInt())
            return DNSPacket(header, questions, answers, authoritites, extra)
        }
    }

    fun toByteArray(): ByteArray {
        val compressor = DNSCompressor()
        val headerByteArray = header.toByteArray()
        val questionByteArray = questions.map { it.toByteArray(compressor, headerByteArray) }
        val questionsList = mutableListOf<Byte>()
        questionByteArray.forEach { it ->
            it.forEach { it2 ->
                questionsList.add(it2)
            }
        }
        var theByteArray = headerByteArray + questionsList.toByteArray()
        theByteArray += answers.toByteArray(compressor, theByteArray)
        theByteArray += authorities.toByteArray(compressor, theByteArray)
        theByteArray += extra.toByteArray(compressor, theByteArray)
        return theByteArray
    }
}
