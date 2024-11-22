package dev.pythonplayer123.kotlindns

import dev.pythonplayer123.kotlindns.builders.zone
import dev.pythonplayer123.kotlindns.dnsobjects.*
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSRRType
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSResourceRecord
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.html.*
import io.ktor.server.netty.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.netty.handler.codec.http.QueryStringDecoder
import kotlinx.html.*

fun hexdump(data: ByteArray): String {
    val perRow = 16

    val hexChars = "0123456789ABCDEF"
    val dump = StringBuilder()
    var chars: StringBuilder? = null
    for (i in data.indices) {
        val offset = i % perRow
        if (offset == 0) {
            chars = StringBuilder()
            dump.append(String.format("%04x", i))
                .append("  ")
        }

        val b = data[i].toInt() and 0xFF
        dump.append(hexChars[b ushr 4])
            .append(hexChars[b and 0xF])
            .append(' ')

        chars!!.append((if ((b >= ' '.code && b <= '~'.code)) b else '.'.code).toChar())

        if (i == data.size - 1 || offset == perRow - 1) {
            for (j in perRow - offset - 1 downTo 1) dump.append("-- ")
            dump.append("  ")
                .append(chars)
                .append('\n')
        }
    }
    return dump.toString()
}

fun main(args: Array<String>) {
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
    }

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
                            0x0000u,
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
    }.start(wait = true)
}
