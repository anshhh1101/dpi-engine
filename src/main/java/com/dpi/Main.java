package com.dpi;

import java.util.Optional;

import com.dpi.model.RawPacket;
import com.dpi.pcap.PcapReader;

public class Main {

    public static void main(String[] args) throws Exception {

        String inputFile = args.length > 0 ? args[0] : "test_dpi.pcap";

        System.out.println("========================================");
        System.out.println("  DPI Engine - Day 1: PCAP Reader Test");
        System.out.println("========================================");
        System.out.println("Reading: " + inputFile);
        System.out.println();

        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        int  packetCount = 0;
        long totalBytes  = 0;

        Optional<RawPacket> pkt;
        while ((pkt = reader.readNextPacket()).isPresent()) {
            RawPacket raw = pkt.get();
            packetCount++;
            totalBytes += raw.data.length;

            if (packetCount <= 10) {
                System.out.printf("Packet %3d | time=%-18s | len=%4d bytes%n",
                        packetCount,
                        raw.getTimestamp(),
                        raw.data.length);

                System.out.print("           | hex: ");
                int preview = Math.min(16, raw.data.length);
                for (int i = 0; i < preview; i++) {
                    System.out.printf("%02x ", raw.data[i] & 0xFF);
                }
                System.out.println();
            }
        }

        reader.close();

        System.out.println();
        System.out.println("========================================");
        System.out.printf("  Total packets : %d%n", packetCount);
        System.out.printf("  Total bytes   : %,d%n", totalBytes);
        System.out.printf("  Avg pkt size  : %.0f bytes%n",
                packetCount > 0 ? (double) totalBytes / packetCount : 0);
        System.out.println("========================================");
    }
}