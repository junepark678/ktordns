package dev.pythonplayer123.kotlindns.dnsobjects

enum class DNSOpcode(val opcode: UByte) {
    QUERY(0x0u),
    IQUERY(0x1u),
    STATUS(0x2u);

    companion object {
        fun fromOpcode(opcode: UByte): DNSOpcode {
            return entries.find { it.opcode == opcode }!!
        }
    }
}
