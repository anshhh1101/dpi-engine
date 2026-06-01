package com.dpi.engine;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.dpi.inspector.SNIExtractor;
import com.dpi.model.AppType;
import com.dpi.model.FiveTuple;
import com.dpi.model.Flow;
import com.dpi.model.ParsedPacket;

public class FlowTracker {

    // The core data structure — every unique connection maps to a Flow object
    // FiveTuple is a Java record so equals() and hashCode() are auto-generated
    // This gives us O(1) lookup per packet
    private final Map<FiveTuple, Flow> flowTable = new HashMap<>();

    // Process one parsed packet — update flow state and extract SNI if present
    public Flow processPacket(ParsedPacket parsed) {

        // Build the five-tuple key for this packet
        FiveTuple tuple = new FiveTuple(
                parsed.srcIp,
                parsed.dstIp,
                parsed.srcPort,
                parsed.dstPort,
                parsed.protocol
        );

        // Get existing flow or create a new one — O(1)
        Flow flow = flowTable.computeIfAbsent(tuple, k -> new Flow(k));

        // Update packet and byte counters
        flow.packetCount++;
        flow.byteCount += parsed.rawData.length;

        // Classify the flow if not already classified
        // Only attempt SNI on HTTPS (port 443) TCP packets with payload
        if (flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS) {

            if (parsed.hasTcp && parsed.dstPort == 443
                    && parsed.payloadLength > 0) {

                // Try to extract SNI from TLS Client Hello
                var sni = SNIExtractor.extractSNI(
                        parsed.rawData,
                        parsed.payloadOffset,
                        parsed.payloadLength);

                if (sni.isPresent()) {
                    flow.sni     = sni.get();
                    flow.appType = SNIExtractor.classifyBySNI(flow.sni);
                } else if (flow.appType == AppType.UNKNOWN) {
                    // Port 443 but no SNI yet — mark as HTTPS until we see Client Hello
                    flow.appType = AppType.HTTPS;
                }

            } else if (parsed.hasTcp && parsed.dstPort == 80) {
                flow.appType = AppType.HTTP;

            } else if (parsed.hasUdp && parsed.dstPort == 53) {
                flow.appType = AppType.DNS;
            }
        }

        return flow;
    }

    // ── Getters for reporting ─────────────────────────────────────────────────

    public Collection<Flow> getAllFlows() {
        return flowTable.values();
    }

    public int getTotalFlows() {
        return flowTable.size();
    }

    // Count how many flows have a specific AppType
    public long countByAppType(AppType appType) {
        return flowTable.values().stream()
                .filter(f -> f.appType == appType)
                .count();
    }

    // Count total packets across all flows
    public long getTotalPackets() {
        return flowTable.values().stream()
                .mapToLong(f -> f.packetCount)
                .sum();
    }
}