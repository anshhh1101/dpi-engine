package com.dpi.engine;

import com.dpi.model.AppType;
import com.dpi.model.Flow;
import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;
import com.dpi.parser.PacketParser;
import com.dpi.pcap.PcapReader;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Optional;

public class DpiEngine {

    private final FlowTracker flowTracker = new FlowTracker();
    private int totalPackets = 0;
    private int totalBytes   = 0;
    private int tcpPackets   = 0;
    private int udpPackets   = 0;

    // ── Main processing loop ──────────────────────────────────────────────────
    public void process(String inputFile) throws Exception {

        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        Optional<RawPacket> pkt;
        while ((pkt = reader.readNextPacket()).isPresent()) {
            RawPacket raw = pkt.get();
            totalPackets++;
            totalBytes += raw.data.length;

            ParsedPacket parsed = PacketParser.parse(raw);
            if (!parsed.isIPv4) continue;

            if (parsed.hasTcp) tcpPackets++;
            if (parsed.hasUdp) udpPackets++;

            // Hand off to FlowTracker — it handles all state management
            flowTracker.processPacket(parsed);
        }

        reader.close();
    }

    // ── Print the full report ─────────────────────────────────────────────────
    public void printReport() {

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║              DPI ENGINE — FLOW REPORT            ║");
        System.out.println("╠══════════════════════════════════════════════════╣");
        System.out.printf( "║  Total Packets  : %-30d║%n", totalPackets);
        System.out.printf( "║  Total Bytes    : %-30d║%n", totalBytes);
        System.out.printf( "║  TCP Packets    : %-30d║%n", tcpPackets);
        System.out.printf( "║  UDP Packets    : %-30d║%n", udpPackets);
        System.out.printf( "║  Unique Flows   : %-30d║%n", flowTracker.getTotalFlows());
        System.out.println("╠══════════════════════════════════════════════════╣");
        System.out.println("║           APPLICATION BREAKDOWN                  ║");
        System.out.println("╠══════════════════════════════════════════════════╣");

        // Count packets per AppType
        Map<AppType, Integer> appCounts = new LinkedHashMap<>();
        for (Flow flow : flowTracker.getAllFlows()) {
            appCounts.merge(flow.appType, flow.packetCount, Integer::sum);
        }

        // Sort by count descending
        List<Map.Entry<AppType, Integer>> sorted = new ArrayList<>(appCounts.entrySet());
        sorted.sort(Map.Entry.comparingByValue(Comparator.reverseOrder()));

        for (Map.Entry<AppType, Integer> entry : sorted) {
            double pct = totalPackets > 0
                    ? (entry.getValue() * 100.0 / totalPackets) : 0;
            String bar = "█".repeat(Math.min((int)(pct / 5), 10));
            System.out.printf("║  %-12s %3d pkts  %5.1f%%  %-10s║%n",
                    entry.getKey(), entry.getValue(), pct, bar);
        }

        System.out.println("╠══════════════════════════════════════════════════╣");
        System.out.println("║              DETECTED SNIs                       ║");
        System.out.println("╠══════════════════════════════════════════════════╣");

        // Print all flows that have an SNI
        flowTracker.getAllFlows().stream()
                .filter(f -> !f.sni.isEmpty())
                .sorted(Comparator.comparing(f -> f.sni))
                .forEach(f -> System.out.printf(
                        "║  %-35s → %-8s║%n", f.sni, f.appType));

        System.out.println("╚══════════════════════════════════════════════════╝");
    }
}