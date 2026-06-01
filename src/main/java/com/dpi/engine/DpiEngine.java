package com.dpi.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.dpi.model.AppType;
import com.dpi.model.Flow;
import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;
import com.dpi.parser.PacketParser;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.PcapWriter;

public class DpiEngine {

    private final FlowTracker flowTracker = new FlowTracker();
    private final RuleEngine  ruleEngine  = new RuleEngine();

    private int totalPackets = 0;
    private int totalBytes   = 0;
    private int tcpPackets   = 0;
    private int udpPackets   = 0;
    private int forwarded    = 0;
    private int dropped      = 0;

    // ── Rule configuration ────────────────────────────────────────────────────

    public void blockIp(String ip)       { ruleEngine.blockIp(ip); }
    public void blockApp(AppType app)    { ruleEngine.blockApp(app); }
    public void blockDomain(String d)    { ruleEngine.blockDomain(d); }

    // ── Main processing loop ──────────────────────────────────────────────────

    public void process(String inputFile, String outputFile) throws Exception {

        PcapReader reader = new PcapReader();
        PcapWriter writer = new PcapWriter();

        reader.open(inputFile);
        writer.open(outputFile);

        Optional<RawPacket> pkt;
        while ((pkt = reader.readNextPacket()).isPresent()) {
            RawPacket raw = pkt.get();
            totalPackets++;
            totalBytes += raw.data.length;

            ParsedPacket parsed = PacketParser.parse(raw);
            if (!parsed.isIPv4) {
                // Non-IP traffic — forward as-is
                writer.writePacket(raw.data, raw.timestampSec, raw.timestampUsec);
                forwarded++;
                continue;
            }

            if (parsed.hasTcp) tcpPackets++;
            if (parsed.hasUdp) udpPackets++;

            // Update flow state (SNI extraction happens here)
            Flow flow = flowTracker.processPacket(parsed);

            // Convert src IP int to string for rule check
            String srcIpStr = PacketParser.intToIp(parsed.srcIp);

            // Check if this flow should be blocked
            boolean block = ruleEngine.isBlocked(srcIpStr, flow.appType, flow.sni);

            if (block) {
                flow.blocked = true;
            }

            // Flow-based decision: if flow is marked blocked, drop ALL its packets
            if (flow.blocked) {
                dropped++;
            } else {
                writer.writePacket(raw.data, raw.timestampSec, raw.timestampUsec);
                forwarded++;
            }
        }

        reader.close();
        writer.close();
    }

    // ── Print the full report ─────────────────────────────────────────────────

    public void printReport() {
        System.out.println();
        System.out.println("=================================================");
        System.out.println("         DPI ENGINE - PROCESSING REPORT          ");
        System.out.println("=================================================");
        System.out.printf("  Total Packets  : %d%n",   totalPackets);
        System.out.printf("  Total Bytes    : %,d%n",  totalBytes);
        System.out.printf("  TCP Packets    : %d%n",   tcpPackets);
        System.out.printf("  UDP Packets    : %d%n",   udpPackets);
        System.out.printf("  Unique Flows   : %d%n",   flowTracker.getTotalFlows());
        System.out.println("-------------------------------------------------");
        System.out.printf("  Forwarded      : %d%n",   forwarded);
        System.out.printf("  Dropped        : %d%n",   dropped);
        System.out.println("=================================================");
        System.out.println("         APPLICATION BREAKDOWN                   ");
        System.out.println("=================================================");

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
            // Check if this app type is blocked
            boolean isBlocked = flowTracker.getAllFlows().stream()
                    .anyMatch(f -> f.appType == entry.getKey() && f.blocked);
            System.out.printf("  %-12s %3d pkts  %5.1f%%%s%n",
                    entry.getKey(),
                    entry.getValue(),
                    pct,
                    isBlocked ? "  [BLOCKED]" : "");
        }

        System.out.println("=================================================");
        System.out.println("         DETECTED SNIs                           ");
        System.out.println("=================================================");

        flowTracker.getAllFlows().stream()
                .filter(f -> !f.sni.isEmpty())
                .sorted(Comparator.comparing(f -> f.sni))
                .forEach(f -> System.out.printf("  %-35s -> %-10s%s%n",
                        f.sni, f.appType,
                        f.blocked ? " [BLOCKED]" : ""));

        System.out.println("=================================================");
    }
}