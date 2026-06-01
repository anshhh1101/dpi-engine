package com.dpi;

import java.util.Optional;

import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;
import com.dpi.parser.PacketParser;
import com.dpi.pcap.PcapReader;

public class Main {

    public static void main(String[] args) throws Exception {

        String inputFile = args.length > 0 ? args[0] : "test_dpi.pcap";

        System.out.println("========================================");
        System.out.println("  DPI Engine - Day 2: Packet Parser");
        System.out.println("========================================");
        System.out.println();

        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        int packetCount = 0;
        int tcpCount    = 0;
        int udpCount    = 0;
        int otherCount  = 0;

        Optional<RawPacket> pkt;
        while ((pkt = reader.readNextPacket()).isPresent()) {
            RawPacket raw = pkt.get();
            packetCount++;

            ParsedPacket parsed = PacketParser.parse(raw);

            if (!parsed.isIPv4) {
                otherCount++;
                System.out.printf("Packet %3d | Non-IPv4 (EtherType: 0x%04x)%n",
                        packetCount, parsed.etherType);
                continue;
            }

            String proto = parsed.hasTcp ? "TCP" : parsed.hasUdp ? "UDP" : "OTHER";
            if (parsed.hasTcp) tcpCount++;
            else if (parsed.hasUdp) udpCount++;
            else otherCount++;

            System.out.printf("Packet %3d | %s  %-15s:%-5d  →  %-15s:%-5d | payload=%d bytes%n",
                    packetCount,
                    proto,
                    PacketParser.intToIp(parsed.srcIp), parsed.srcPort,
                    PacketParser.intToIp(parsed.dstIp), parsed.dstPort,
                    parsed.payloadLength);
        }

        reader.close();

        System.out.println();
        System.out.println("========================================");
        System.out.printf("  Total   : %d packets%n", packetCount);
        System.out.printf("  TCP     : %d%n", tcpCount);
        System.out.printf("  UDP     : %d%n", udpCount);
        System.out.printf("  Other   : %d%n", otherCount);
        System.out.println("========================================");
    }
}