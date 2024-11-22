package dev.pythonplayer123.kotlindns.dnsobjects

import java.util.*

class DNSHeaderFlags(
    var qr: Boolean,
    var opcode: DNSOpcode,
    var authoritative: Boolean,
    var truncation: Boolean,
    var recurse: Boolean,
    var canRecurse: Boolean,
    var rcode: DNSRcode
) {
    fun responseHeaders(): DNSHeaderFlags {
        qr = !qr
        return this
    }
    companion object {
        fun parse(data: ByteArray): DNSHeaderFlags {
            val bitSet = BitSet(16)
            for (i in data.indices) {
                for (j in 0..7) {
                    if ((data[i].toInt() shr (7 - j) and 1) == 1) {
                        bitSet.set(i * 8 + j)
                    }
                }
            }

            val qr = bitSet[0]
            var rawOpcode: UByte = 0u
            for (i in 1..4) {
                if (bitSet[i]) {
                    rawOpcode = rawOpcode or (1u shl i).toUByte()
                }
            }

            val opcode = DNSOpcode.fromOpcode(rawOpcode)
            val authoritative = bitSet[5]
            val truncation = bitSet[6]
            val recurse = bitSet[7]
            val canRecurse = bitSet[8]
            val rawRcode: UByte = 0u

            for (i in 12..15) {
                if (bitSet[i]) {
                    rawOpcode = rawOpcode or (1u shl i).toUByte()
                }
            }

            val rcode = DNSRcode.fromRcode(rawRcode)

            return DNSHeaderFlags(qr, opcode, authoritative, truncation, recurse, canRecurse, rcode)
        }
    }

    fun toByteArray(): ByteArray {
        val bitSet = BitSet(16)
        bitSet[0] = qr

        for (i in 1 until 5) {
            if ((opcode.opcode.toInt() shr (i - 1)) and 1 == 1) {
                bitSet.set(5 - i)
            }
        }
        bitSet[5] = authoritative
        bitSet[6] = truncation
        bitSet[7] = recurse
        bitSet[8] = canRecurse

        for (i in 12 until 16) {
            if ((rcode.rcode.toInt() shr (i - 12)) and 1 == 1) {
                bitSet.set(16 - i + 11)
            }
        }

        var str = ""

        for (i in 0 until 8) {
            if (bitSet[i]) {
                str += '1'
            } else {
                str += '0'
            }
        }

        val byte1 = str.toUByte(2)
        str = ""

        for (i in 8 until 16) {
            if (bitSet[i]) {
                str += '1'
            } else {
                str += '0'
            }
        }


        val byte2 = str.toUByte(2)

        return byteArrayOf(byte1.toByte(), byte2.toByte())
    }
}
