package dev.pythonplayer123.kotlindns

import com.google.common.net.InetAddresses
import dev.pythonplayer123.kotlindns.builders.zone
import dev.pythonplayer123.kotlindns.dnsobjects.*
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSAAAAResource
import dev.pythonplayer123.kotlindns.dnsobjects.resourcerecords.DNSResourceRecord
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.*
import java.net.Inet6Address

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
    runBlocking {
        val selectorManager = SelectorManager(Dispatchers.IO)
        val serverSocket = aSocket(selectorManager).udp().bind(InetSocketAddress("127.0.0.1", 8080))
        println("Server is listening at ${serverSocket.localAddress}")

        while (true) {
            val packet = serverSocket.receive()
            val bytes = packet.packet.readBytes()
            val dnsPacket = DNSPacket.parse(bytes)
            val dnsQueries = mutableListOf<DNSResourceRecord>()
            for (question in dnsPacket.questions) {
                val something = myZone.query(question)
                for (some in something) {
                    dnsQueries.add(some)
                }
            }
            val resp = DNSPacket(dnsPacket, dnsQueries, myZone.authorities, mutableListOf())
            serverSocket.send(Datagram(ByteReadPacket(resp.toByteArray()), packet.address))
        }
    }
}
