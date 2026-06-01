package com.dpi.parser;

import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;

public class PacketParser {

    // Ethernet header is always exactly 14 bytes
    private static final int ETHERNET_HEADER_LEN = 14;

    // EtherType value for IPv4
    private static final int ETHERTYPE_IPV4 = 0x0800;

    public static ParsedPacket parse(RawPacket raw) {
        ParsedPacket parsed = new ParsedPacket();
        parsed.rawData = raw.data;
        byte[] data = raw.data;

        // Need at least 14 bytes for Ethernet header
        if (data.length < ETHERNET_HEADER_LEN) return parsed;

        // ── Step 1: Parse Ethernet Header (bytes 0-13) ──────────────────────
        // Bytes 0-5:   Destination MAC
        // Bytes 6-11:  Source MAC
        // Bytes 12-13: EtherType
        parsed.dstMac = parseMac(data, 0);
        parsed.srcMac = parseMac(data, 6);
        parsed.etherType = readUint16(data, 12);

        // Only handle IPv4 for now
        if (parsed.etherType != ETHERTYPE_IPV4) return parsed;
        if (data.length < ETHERNET_HEADER_LEN + 20) return parsed;

        // ── Step 2: Parse IP Header (starts at byte 14) ──────────────────────
        // Byte 0 of IP header: upper 4 bits = version, lower 4 bits = IHL
        int ipStart = ETHERNET_HEADER_LEN;
        int version = (data[ipStart] & 0xFF) >> 4;
        if (version != 4) return parsed;  // Only IPv4

        // IHL = IP Header Length in 32-bit words — multiply by 4 to get bytes
        // Example: IHL=5 means 5 x 4 = 20 bytes (minimum IP header)
        int ihl = (data[ipStart] & 0x0F) * 4;
        if (ihl < 20) return parsed;

        // Byte 9 of IP header = protocol (6=TCP, 17=UDP)
        parsed.protocol = data[ipStart + 9] & 0xFF;
        parsed.ttl      = data[ipStart + 8] & 0xFF;

        // Bytes 12-15 of IP header = source IP (4 bytes)
        // Bytes 16-19 of IP header = destination IP (4 bytes)
        parsed.srcIp = readInt32(data, ipStart + 12);
        parsed.dstIp = readInt32(data, ipStart + 16);
        parsed.isIPv4 = true;

        int transportStart = ipStart + ihl;

        // ── Step 3: Parse TCP Header ─────────────────────────────────────────
        if (parsed.protocol == 6) {
            if (data.length < transportStart + 20) return parsed;

            // Bytes 0-1 of TCP header = source port
            // Bytes 2-3 of TCP header = destination port
            parsed.srcPort = readUint16(data, transportStart);
            parsed.dstPort = readUint16(data, transportStart + 2);

            // Byte 12 of TCP header: upper 4 bits = data offset (in 32-bit words)
            // This tells us where the actual payload starts
            int dataOffset = ((data[transportStart + 12] & 0xFF) >> 4) * 4;
            if (dataOffset < 20) dataOffset = 20;

            parsed.payloadOffset = transportStart + dataOffset;
            parsed.payloadLength = data.length - parsed.payloadOffset;
            if (parsed.payloadLength < 0) parsed.payloadLength = 0;
            parsed.hasTcp = true;
        }

        // ── Step 4: Parse UDP Header ─────────────────────────────────────────
        else if (parsed.protocol == 17) {
            if (data.length < transportStart + 8) return parsed;

            // UDP header is always 8 bytes
            // Bytes 0-1 = source port, bytes 2-3 = destination port
            parsed.srcPort = readUint16(data, transportStart);
            parsed.dstPort = readUint16(data, transportStart + 2);

            parsed.payloadOffset = transportStart + 8;
            parsed.payloadLength = data.length - parsed.payloadOffset;
            if (parsed.payloadLength < 0) parsed.payloadLength = 0;
            parsed.hasUdp = true;
        }

        return parsed;
    }

    // ── Helper: read 2 bytes as unsigned 16-bit big-endian int ───────────────
    public static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    // ── Helper: read 4 bytes as signed 32-bit big-endian int ─────────────────
    // Network protocols use big-endian (most significant byte first)
    public static int readInt32(byte[] data, int offset) {
        return ((data[offset]     & 0xFF) << 24) |
               ((data[offset + 1] & 0xFF) << 16) |
               ((data[offset + 2] & 0xFF) <<  8) |
               ( data[offset + 3] & 0xFF);
    }

    // ── Helper: format 6 bytes as MAC address string ─────────────────────────
    private static String parseMac(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                data[offset]   & 0xFF, data[offset+1] & 0xFF,
                data[offset+2] & 0xFF, data[offset+3] & 0xFF,
                data[offset+4] & 0xFF, data[offset+5] & 0xFF);
    }

    // ── Helper: convert int IP to readable string (e.g. 192.168.1.10) ────────
    public static String intToIp(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >>  8) & 0xFF) + "." +
               ( ip        & 0xFF);
    }
}