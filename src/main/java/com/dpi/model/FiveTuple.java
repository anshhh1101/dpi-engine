package com.dpi.model;

public record FiveTuple(
    int srcIp, int dstIp,
    int srcPort, int dstPort,
    int protocol
) {
    public String srcIpStr() { return intToIp(srcIp); }
    public String dstIpStr() { return intToIp(dstIp); }

    private static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >>  8) & 0xFF) + "." +
               ( ip        & 0xFF);
    }

    public String protocolStr() {
        return switch (protocol) {
            case 6  -> "TCP";
            case 17 -> "UDP";
            default -> "OTHER(" + protocol + ")";
        };
    }

    @Override
    public String toString() {
        return srcIpStr() + ":" + srcPort +
               " -> " + dstIpStr() + ":" + dstPort +
               " [" + protocolStr() + "]";
    }
}