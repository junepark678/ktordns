package dev.pythonplayer123.kotlindns.utils

class DNSCompressor {
    private val labelDict = mutableMapOf<String, Int>()

    fun compressName(name: String, message: ByteArray): ByteArray {
        val existingOffset = labelDict[name]
        if (existingOffset != null) {
            return getPointer(existingOffset)
        }

        val labels = name.split(".")
        var offset = message.size
        val compressedName = mutableListOf<Byte>()
        var flag = false
        for (i in labels.indices) {
            val currentName = labels.drop(i).joinToString(".")
            if (labelDict.containsKey(currentName)) {
                compressedName.addAll(getPointer(labelDict[currentName]!!).toList())
                flag = true
                break
            } else {
                compressedName.addAll(encodeLabel(labels[i]).toList())
                labelDict[currentName] = offset
                offset += labels[i].length + 1
            }
        }
        if (!flag) {
            compressedName.add(0)
        }
        return compressedName.toByteArray()
    }

    private fun encodeLabel(label: String): ByteArray {
        val length = label.length
        return byteArrayOf(length.toByte()) + label.toByteArray(Charsets.UTF_8)
    }

    private fun getPointer(offset: Int): ByteArray {
        val pointer = 0xC000 or offset
        return byteArrayOf((pointer shr 8).toByte(), pointer.toByte())
    }
}

