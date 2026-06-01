package com.dpi.engine;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.dpi.inspector.HTTPExtractor;
import com.dpi.inspector.SNIExtractor;
import com.dpi.model.AppType;
import com.dpi.model.FiveTuple;
import com.dpi.model.Flow;
import com.dpi.model.ParsedPacket;

public class FlowTracker {

    private final Map<FiveTuple, Flow> flowTable = new HashMap<>();

    public Flow processPacket(ParsedPacket parsed) {

        FiveTuple tuple = new FiveTuple(
                parsed.srcIp, parsed.dstIp,
                parsed.srcPort, parsed.dstPort,
                parsed.protocol);

        Flow flow = flowTable.computeIfAbsent(tuple, k -> new Flow(k));

        flow.packetCount++;
        flow.byteCount += parsed.rawData.length;

        // Only classify if not yet identified
        if (flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS
                || flow.appType == AppType.HTTP) {

            // ── HTTPS: extract SNI from TLS Client Hello ──────────────────
            if (parsed.hasTcp && parsed.dstPort == 443
                    && parsed.payloadLength > 0) {

                var sni = SNIExtractor.extractSNI(
                        parsed.rawData,
                        parsed.payloadOffset,
                        parsed.payloadLength);

                if (sni.isPresent()) {
                    flow.sni     = sni.get();
                    flow.appType = SNIExtractor.classifyBySNI(flow.sni);
                } else if (flow.appType == AppType.UNKNOWN) {
                    flow.appType = AppType.HTTPS;
                }

            // ── HTTP: extract Host header ─────────────────────────────────
            } else if (parsed.hasTcp && parsed.dstPort == 80
                    && parsed.payloadLength > 0) {

                var host = HTTPExtractor.extractHost(
                        parsed.rawData,
                        parsed.payloadOffset,
                        parsed.payloadLength);

                if (host.isPresent()) {
                    flow.sni     = host.get();   // reuse sni field for host
                    flow.appType = SNIExtractor.classifyBySNI(flow.sni);
                    // If not a known app, mark as HTTP
                    if (flow.appType == AppType.HTTPS
                            || flow.appType == AppType.UNKNOWN) {
                        flow.appType = AppType.HTTP;
                    }
                } else {
                    flow.appType = AppType.HTTP;
                }

            // ── DNS ───────────────────────────────────────────────────────
            } else if (parsed.hasUdp && parsed.dstPort == 53) {
                flow.appType = AppType.DNS;
            }
        }

        return flow;
    }

    public Collection<Flow> getAllFlows() { return flowTable.values(); }
    public int getTotalFlows()           { return flowTable.size(); }

    public long countByAppType(AppType appType) {
        return flowTable.values().stream()
                .filter(f -> f.appType == appType).count();
    }

    public long getTotalPackets() {
        return flowTable.values().stream()
                .mapToLong(f -> f.packetCount).sum();
    }
}