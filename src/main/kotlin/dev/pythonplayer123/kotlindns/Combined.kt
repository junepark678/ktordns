package dev.pythonplayer123.kotlindns

import com.google.common.net.InetAddresses
import dev.pythonplayer123.kotlindns.builders.zone
import dev.pythonplayer123.kotlindns.dnsobjects.*
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSAAAAResource
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSRRType
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSResourceRecord
import dev.pythonplayer123.kotlindns.utils.readShort
import io.ktor.http.*
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.html.*
import io.ktor.server.netty.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.html.*
import java.net.Inet6Address

fun main() {
    val myZone = zone {
        domain = "pythonplayer123.xyz"
        baseTTL = 60u
        records {
            a {
                domain = "clang"
                ipAddress = "127.0.0.1"
            }
            cname {
                domain = "gcc"
                cname = "clang.pythonplayer123.xyz"
            }
            ns {
                domain = ""
                server = "ns.pythonplayer123.dev"
            }
            aaaa {
                domain = "ipv6"
                ipAddress = "::1"
            }
        }
        rule {
            regex = """.*pythonplayer123\.(dev|xyz)""".toRegex(RegexOption.DOT_MATCHES_ALL)
            handler { _, dnsQuestion ->
                val address = InetAddresses.forString("::1")

                if (address !is Inet6Address) {
                    throw Exception("what the...")
                }


                return@handler listOf(
                    DNSAAAAResource(
                        dnsQuestion.qname,
                        dnsQuestion.qclass,
                        60u,
                        address
                    )
                )
            }
        }
    }
    try {
        embeddedServer(Netty, port = 8080) {
            routing {
                get("/") {
                    call.respondHtml(HttpStatusCode.OK) {
                        head {
                            title {
                                +"DNS Server"
                            }
                        }
                        body {
                            h1 { +"DNS Server" }
                            form(method = FormMethod.post, action = "/query") {
                                input(type = InputType.text, name = "domain") {
                                    placeholder = "Enter a domain..."
                                }
                                p { +"select a type" }
                                select {
                                    name = "type"
                                    option {
                                        value = "A"
                                        +"A"
                                    }
                                    option {
                                        value = "AAAA"
                                        +"AAAA"
                                    }
                                    option {
                                        value = "NS"
                                        +"NS"
                                    }
                                    option {
                                        value = "CNAME"
                                        +"CNAME"
                                    }
                                }
                                submitInput()
                            }
                        }
                    }
                }

                post("/query") {
                    val query = call.receiveParameters()
                    val dnsResourceRecords: List<DNSResourceRecord>
                    val domain = query["domain"] ?: return@post call.respondText(
                        "invalid query",
                        status = HttpStatusCode.PaymentRequired
                    )
                    val type = query["type"] ?: return@post call.respondText(
                        "invalid query",
                        status = HttpStatusCode.PaymentRequired
                    )
                    val resp: DNSPacket
                    try {
                        val qtype = when (type) {
                            "A" -> DNSRRType.A
                            "AAAA" -> DNSRRType.AAAA
                            "NS" -> DNSRRType.NS
                            "CNAME" -> DNSRRType.CNAME
                            else -> {
                                return@post call.respondText("invalid query", status = HttpStatusCode.PaymentRequired)
                            }
                        }

                        val question = DNSQuestion(domain, qtype, DNSQueryClass.IN)
                        dnsResourceRecords = myZone.query(question) ?: listOf()
                        resp = DNSPacket(
                            DNSHeader(
                                0x6969u,
                                DNSHeaderFlags(true, DNSOpcode.QUERY, true, false, false, false, DNSRcode.NOERROR),
                                1u,
                                1u,
                                0u,
                                0u
                            ), listOf(question), myZone.authorities, mutableListOf(), mutableListOf()
                        )
                    } catch (e: Exception) {
                        return@post call.respondText("invalid query", status = HttpStatusCode.PaymentRequired)
                    }

                    call.respondHtml(HttpStatusCode.OK) {
                        head {
                            title { +"DNS Server" }
                        }
                        body {
                            h1 { +"DNS Server" }
                            // results
                            table {
                                thead {
                                    tr {
                                        th(scope = ThScope.col) { +"Name" }
                                        th(scope = ThScope.col) { +"Type" }
                                        th(scope = ThScope.col) { +"Class" }
                                        th(scope = ThScope.col) { +"TTL" }
                                        th(scope = ThScope.col) { +"Value" }
                                    }
                                }
                                tbody {
                                    dnsResourceRecords.forEach {
                                        tr {
                                            th(scope = ThScope.row) {
                                                +it.name
                                            }
                                            th { +it.type.name }
                                            th { +it.dnsClass.name }
                                            th { +it.ttl.toString() }
                                            th { +it.toString() }
                                        }
                                    }
                                }
                            }
                            pre { +hexdump(resp.toByteArray()) }
                        }
                    }
                }
            }
        }.start()
    } catch (e: Exception) {
        println(e.stackTraceToString())
    }
    runBlocking {
        val selectorManager = SelectorManager(Dispatchers.IO)
        val serverSocket = aSocket(selectorManager).udp().bind(InetSocketAddress("::1", 8080))
        println("Server is listening at ${serverSocket.localAddress}")

        while (true) {
            val packet = serverSocket.receive()
            val bytes = packet.packet.readBytes()
            try {
                val dnsPacket = DNSPacket.parse(bytes)
                val dnsQueries = mutableListOf<DNSResourceRecord>()
                for (question in dnsPacket.questions) {
                    val something = myZone.query(question) ?: continue
                    for (some in something)
                        dnsQueries.add(some)
                }
                val resp = DNSPacket(dnsPacket, dnsQueries, myZone.authorities, mutableListOf())
                serverSocket.send(Datagram(ByteReadPacket(resp.toByteArray()), packet.address))
            } catch (e: Exception) {
                println(e.stackTraceToString())
                val resp = DNSPacket(
                    DNSHeader(
                        bytes.readShort(0),
                        DNSHeaderFlags(false, DNSOpcode.QUERY, true, false, false, false, DNSRcode.SERVFAIL),
                        0u,
                        0u,
                        0u,
                        0u
                    ), listOf(), listOf(), listOf(), listOf()
                )
                serverSocket.send(Datagram(ByteReadPacket(resp.toByteArray()), packet.address))
            }
        }
    }
}
