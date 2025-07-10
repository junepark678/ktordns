package dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords

import kotlin.reflect.KClass

enum class DNSRRType(val value: UShort, val dnsResourceRecordClass: KClass<out DNSResourceRecord>? = null) {
    A(1u, DNSAResource::class),
    AAAA(28u, DNSAAAAResource::class),
    AFSDB(18u, DNSAFSDBResource::class),
    APL(42u),
    CAA(257u, DNSCAAResource::class),
    CDNSKEY(60u),
    CDS(59u),
    CERT(37u, DNSCERTResource::class),
    CNAME(5u, DNSCNAMEResource::class),
    CSYNC(62u),
    DHCID(49u),
    DLV(32769u),
    DNAME(39u, DNSDNAMEResource::class),
    DNSKEY(48u, DNSDNSKEYResource::class),
    DS(43u, DNSDSResource::class),
    EUI48(108u, DNSEUI48Resource::class),
    EUI64(109u, DNSEUI64Resource::class),
    HINFO(13u, DNSHINFOResource::class),
    HIP(55u, DNSHIPResource::class),
    HTTPS(65u, DNSHTTPSResource::class),
    IPSECKEY(45u, DNSIPSECKEYResource::class),
    KEY(25u, DNSKEYResource::class),
    KX(36u, DNSKXResource::class),
    LOC(29u, DNSLOCResource::class),
    MX(15u, DNSMXResource::class),
    NAPTR(35u, DNSNAPTRResource::class),
    NS(2u, DNSNSResource::class),
    NSEC(47u, DNSNSECResource::class),
    NSEC3(50u, DNSNSEC3Resource::class),
    OPENPGPKEY(61u),
    PTR(12u, DNSPTRResource::class),
    RP(17u, DNSRPResource::class),
    RRSIG(46u, DNSRRSIGResource::class),
    SIG(24u),
    SMIMEA(53u, DNSSMIMEAResource::class),
    SOA(6u, DNSSOAResource::class),
    SRV(33u, DNSSRVResource::class),
    SSHFP(44u, DNSSSHFPResource::class),
    SVCB(64u, DNSSVCBResource::class),
    TA(32768u),
    TKEY(249u),
    TLSA(52u, DNSTLSAResource::class),
    TSIG(250u),
    TXT(16u, DNSTXTResource::class),
    URI(256u, DNSURIResource::class),
    ZONEMD(63u),
    OPT(41u, DNSOPTResource::class),    // EDNS
    UNKNOWN(0u);

    companion object {
        fun fromValue(rr: UShort): DNSRRType {
            return entries.find { it.value == rr }!!
        }
    }
}

