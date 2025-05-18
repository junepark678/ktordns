package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import kotlin.reflect.KClass

enum class DNSRRType(val value: UShort, val dnsResourceRecordClass: KClass<out DNSResourceRecord>? = null) {
    A(1u, DNSAResource::class),
    AAAA(28u, DNSAAAAResource::class),
    AFSDB(18u),
    APL(42u),
    CAA(257u),
    CDNSKEY(60u),
    CDS(59u),
    CERT(37u),
    CNAME(5u, DNSCNAMEResource::class),
    CSYNC(62u),
    DHCID(49u),
    DLV(32769u),
    DNAME(39u),
    DNSKEY(48u),
    DS(43u),
    EUI48(108u),
    EUI64(109u),
    HINFO(13u),
    HIP(55u),
    HTTPS(65u),
    IPSECKEY(45u),
    KEY(25u),
    KX(36u),
    LOC(29u),
    MX(15u),
    NAPTR(35u),
    NS(2u, DNSNSResource::class),
    NSEC(47u),
    NSEC3(50u),
    OPENPGPKEY(61u),
    PTR(12u),
    RP(17u),
    RRSIG(46u),
    SIG(24u),
    SMIMEA(53u),
    SOA(6u),
    SRV(33u),
    SSHFP(44u),
    SVCB(64u),
    TA(32768u),
    TKEY(249u),
    TLSA(52u),
    TSIG(250u),
    TXT(16u),
    URI(256u),
    ZONEMD(63u),
    OPT(41u),    // EDNS
    UNKNOWN(0u);

    companion object {
        fun fromValue(rr: UShort): DNSRRType {
            return entries.find { it.value == rr }!!
        }
    }
}

