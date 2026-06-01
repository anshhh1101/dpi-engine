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

    public void blockIp(String ip)     { ruleEngine.blockIp(ip); }
    public void blockApp(AppType app)  { ruleEngine.blockApp(app); }
    public void blockDomain(String d)  { ruleEngine.blockDomain(d); }

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
                writer.writePacket(raw.data, raw.timestampSec, raw.timestampUsec);
                forwarded++;
                continue;
            }

            if (parsed.hasTcp) tcpPackets++;
            if (parsed.hasUdp) udpPackets++;

            Flow flow = flowTracker.processPacket(parsed);
            String srcIpStr = PacketParser.intToIp(parsed.srcIp);

            if (ruleEngine.isBlocked(srcIpStr, flow.appType, flow.sni)) {
                flow.blocked = true;
            }

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

    public void printReport() {
        int w = 52;
        String line = "=".repeat(w);
        String thin = "-".repeat(w);

        System.out.println();
        System.out.println(line);
        System.out.println(center("DPI ENGINE - FINAL REPORT", w));
        System.out.println(line);
        System.out.printf("  %-20s : %d%n",    "Total Packets",  totalPackets);
        System.out.printf("  %-20s : %,d bytes%n","Total Bytes", totalBytes);
        System.out.printf("  %-20s : %d%n",    "TCP Packets",    tcpPackets);
        System.out.printf("  %-20s : %d%n",    "UDP Packets",    udpPackets);
        System.out.printf("  %-20s : %d%n",    "Unique Flows",   flowTracker.getTotalFlows());
        System.out.println(thin);
        System.out.printf("  %-20s : %d%n",    "Forwarded",      forwarded);
        System.out.printf("  %-20s : %d%n",    "Dropped",        dropped);
        System.out.println(line);

        // App breakdown
        System.out.println(center("APPLICATION BREAKDOWN", w));
        System.out.println(line);

        Map<AppType, int[]> appStats = new LinkedHashMap<>();
        for (Flow flow : flowTracker.getAllFlows()) {
            appStats.computeIfAbsent(flow.appType, k -> new int[2]);
            appStats.get(flow.appType)[0] += flow.packetCount;
            if (flow.blocked) appStats.get(flow.appType)[1] = 1;
        }

        List<Map.Entry<AppType, int[]>> sorted = new ArrayList<>(appStats.entrySet());
        sorted.sort((a, b) -> b.getValue()[0] - a.getValue()[0]);

        for (var entry : sorted) {
            double pct = totalPackets > 0
                    ? (entry.getValue()[0] * 100.0 / totalPackets) : 0;
            int bars = Math.min((int)(pct / 5), 12);
            String bar = "#".repeat(bars);
            boolean blocked = entry.getValue()[1] == 1;
            System.out.printf("  %-12s %3d  %5.1f%%  %-14s%s%n",
                    entry.getKey(),
                    entry.getValue()[0],
                    pct,
                    bar,
                    blocked ? " [BLOCKED]" : "");
        }

        System.out.println(line);

        // SNI/Host list
        System.out.println(center("DETECTED DOMAINS", w));
        System.out.println(line);

        flowTracker.getAllFlows().stream()
                .filter(f -> !f.sni.isEmpty())
                .sorted(Comparator.comparing(f -> f.sni))
                .forEach(f -> System.out.printf("  %-32s %-10s%s%n",
                        f.sni, f.appType,
                        f.blocked ? " [BLOCKED]" : ""));

        System.out.println(line);
        System.out.printf("  Output written to: output.pcap%n");
        System.out.printf("  Open in Wireshark to verify blocked traffic%n");
        System.out.println(line);
    }

    private String center(String text, int width) {
        int pad = (width - text.length()) / 2;
        return " ".repeat(Math.max(0, pad)) + text;
    }
}