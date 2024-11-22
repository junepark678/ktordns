package dev.pythonplayer123.kotlindns.dnsobjects

enum class DNSQueryClass(val value: UShort) {
    IN(1u),
    CH(3u),
    HS(4u),
    NONE(254u),
    ANY(255u);

    companion object {
        fun fromValue(value: UShort): DNSQueryClass {
            return entries.find { it.value == value }!!
        }
    }
}
