package com.dpi;

import java.util.Optional;

import com.dpi.inspector.SNIExtractor;
import com.dpi.model.AppType;
import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;
import com.dpi.parser.PacketParser;
import com.dpi.pcap.PcapReader;

public class Main {

    public static void main(String[] args) throws Exception {

        String inputFile = args.length > 0 ? args[0] : "test_dpi.pcap";

        System.out.println("========================================");
        System.out.println("  DPI Engine - Day 3: SNI Extractor");
        System.out.println("========================================");
        System.out.println();

        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        int packetCount = 0;
        int sniFound    = 0;

        Optional<RawPacket> pkt;
        while ((pkt = reader.readNextPacket()).isPresent()) {
            RawPacket raw = pkt.get();
            packetCount++;

            ParsedPacket parsed = PacketParser.parse(raw);
            if (!parsed.isIPv4) continue;

            String proto = parsed.hasTcp ? "TCP" : "UDP";

            // Only attempt SNI extraction on HTTPS traffic (port 443)
            // with actual payload bytes
            if (parsed.hasTcp && parsed.dstPort == 443
                    && parsed.payloadLength > 0) {

                Optional<String> sni = SNIExtractor.extractSNI(
                        parsed.rawData,
                        parsed.payloadOffset,
                        parsed.payloadLength);

                if (sni.isPresent()) {
                    sniFound++;
                    AppType app = SNIExtractor.classifyBySNI(sni.get());
                    System.out.printf("Packet %3d | %-15s:%-5d → %-15s:%-5d | SNI: %-30s | App: %s%n",
                            packetCount,
                            PacketParser.intToIp(parsed.srcIp), parsed.srcPort,
                            PacketParser.intToIp(parsed.dstIp), parsed.dstPort,
                            sni.get(), app);
                } else {
                    System.out.printf("Packet %3d | %-15s:%-5d → %-15s:%-5d | HTTPS (no SNI — data packet)%n",
                            packetCount,
                            PacketParser.intToIp(parsed.srcIp), parsed.srcPort,
                            PacketParser.intToIp(parsed.dstIp), parsed.dstPort);
                }

            } else {
                System.out.printf("Packet %3d | %s  %-15s:%-5d → %-15s:%-5d | port %d%n",
                        packetCount, proto,
                        PacketParser.intToIp(parsed.srcIp), parsed.srcPort,
                        PacketParser.intToIp(parsed.dstIp), parsed.dstPort,
                        parsed.dstPort);
            }
        }

        reader.close();

        System.out.println();
        System.out.println("========================================");
        System.out.printf("  Total packets : %d%n", packetCount);
        System.out.printf("  SNI extracted : %d%n", sniFound);
        System.out.println("========================================");
    }
}