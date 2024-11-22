package dev.pythonplayer123.kotlindns.utils

import dev.pythonplayer123.kotlindns.dnsobjects.DNSQueryClass
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSRRType
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSResourceRecord
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*
import kotlin.experimental.and

fun ByteArray.readShort(offset: Int): UShort {
    val result = ((this[offset].toInt() and 0xFF) shl 8) or (this[offset + 1].toInt() and 0xFF)
    return result.toUShort()
}

fun ByteArray.readInt(offset: Int): UInt {
    return (((readShort(offset).toInt() and 0xFFFF) shl 8) or (this[offset + 3].toInt() and 0xFFFF)).toUInt()
}

fun UShort.toBytes(): ByteArray {
    return byteArrayOf((this.toInt() shr 8).toByte(), this.toByte())
}

fun String.toDNSLabel(): ByteArray {
    return toDNSLabelMutableList().toByteArray()
}

fun String.toDNSLabelMutableList(): MutableList<Byte> {
    val encodedQname = mutableListOf<Byte>()
    val qnamelist = split('.')
    for (qnamesec in qnamelist) {
        encodedQname.add(qnamesec.length.toByte())
        for (c in qnamesec) {
            encodedQname.add(c.code.toByte())
        }
    }
    return encodedQname
}

fun ByteArray.decompressName(start: Int): Pair<String, Int> {
    val labels = mutableListOf<String>()
    var offset = start
    var oldoffset = 0
    while (this[offset].toInt() != 0) {
        if ((this[offset].toUByte() and 0xC0u) == 0xC0u.toUByte()) {
            if (oldoffset == 0) oldoffset = offset
            offset = (readShort(offset) xor 0b1100_0000_0000_0000u).toInt()
        } else {
            val end = offset + this[offset]
            var label = ""
            while (offset < end) {
                label += this[++offset].toInt().toChar()
            }
            labels += label
            offset++
        }
    }
    if (oldoffset != 0) {
        offset = oldoffset + 1
    }
    return Pair(labels.joinToString("."), offset + 1)
}

fun MutableList<Byte>.add(dnsRRType: DNSRRType) {
    add(dnsRRType.value)
}

fun MutableList<Byte>.add(dnsQueryClass: DNSQueryClass) {
    add(dnsQueryClass.value)
}

fun MutableList<Byte>.add(int: UShort) {
    add((int.toInt() shr 8).toByte())
    add(int.toByte())
}

fun MutableList<Byte>.add(int: UInt) {
    add((int shr 24).toByte())
    add((int shr 16).toByte())
    add((int shr 8).toByte())
    add(int.toByte())
}

fun List<DNSResourceRecord>.toByteArray(compressor: DNSCompressor, message: ByteArray): ByteArray {
    val answerByteArray = map { it.toByteArray(compressor, message) }
    val answersList = mutableListOf<Byte>()
    answerByteArray.forEach { it ->
        it.forEach { it2 ->
            answersList.add(it2)
        }
    }
    return answersList.toByteArray()
}
