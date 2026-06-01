package com.dpi.inspector;

import java.util.Optional;

import com.dpi.model.AppType;

public class SNIExtractor {

    // TLS constants
    private static final int TLS_HANDSHAKE       = 0x16;  // Content type
    private static final int TLS_CLIENT_HELLO    = 0x01;  // Handshake type
    private static final int SNI_EXTENSION_TYPE  = 0x0000;

    // ── Main entry point ─────────────────────────────────────────────────────
    // Takes the TCP payload bytes and returns the SNI hostname if found
    public static Optional<String> extractSNI(byte[] data, int offset, int length) {
        // Need at least 9 bytes for TLS record + handshake headers
        if (length < 9) return Optional.empty();

        // ── Check 1: TLS Record Header (5 bytes) ─────────────────────────────
        // Byte 0: Content Type must be 0x16 (Handshake)
        if ((data[offset] & 0xFF) != TLS_HANDSHAKE) return Optional.empty();

        // Bytes 1-2: TLS Version (must be 0x0301, 0x0302, or 0x0303)
        int tlsVersionMajor = data[offset + 1] & 0xFF;
        if (tlsVersionMajor != 0x03) return Optional.empty();

        // Bytes 3-4: Record length (we trust it but use our own bounds)
        // ── Check 2: Handshake Header ─────────────────────────────────────────
        // Byte 5: Handshake type must be 0x01 (Client Hello)
        if ((data[offset + 5] & 0xFF) != TLS_CLIENT_HELLO) return Optional.empty();

        // Bytes 6-8: 3-byte handshake length (skip it)
        // ── Navigate Client Hello Body ────────────────────────────────────────
        // Byte 9-10: Client version (skip)
        // Bytes 11-42: Random (32 bytes, skip)
        int pos = offset + 43;  // Now pointing at Session ID Length

        if (pos >= offset + length) return Optional.empty();

        // Skip Session ID
        int sessionIdLen = data[pos] & 0xFF;
        pos += 1 + sessionIdLen;
        if (pos + 2 >= offset + length) return Optional.empty();

        // Skip Cipher Suites
        int cipherSuitesLen = readUint16(data, pos);
        pos += 2 + cipherSuitesLen;
        if (pos + 1 >= offset + length) return Optional.empty();

        // Skip Compression Methods
        int compressionLen = data[pos] & 0xFF;
        pos += 1 + compressionLen;
        if (pos + 2 >= offset + length) return Optional.empty();

        // ── Read Extensions ───────────────────────────────────────────────────
        int extensionsLen = readUint16(data, pos);
        pos += 2;
        int extensionsEnd = pos + extensionsLen;

        // Loop through each extension looking for SNI (type 0x0000)
        while (pos + 4 <= extensionsEnd && pos + 4 <= offset + length) {
            int extType = readUint16(data, pos);
            int extLen  = readUint16(data, pos + 2);
            pos += 4;

            if (extType == SNI_EXTENSION_TYPE) {
                // ── Found SNI Extension! ──────────────────────────────────────
                // Structure inside SNI extension:
                // 2 bytes: SNI list length
                // 1 byte:  SNI type (0x00 = hostname)
                // 2 bytes: hostname length
                // N bytes: hostname string
                if (pos + 5 > offset + length) return Optional.empty();

                // Skip SNI list length (2 bytes) and SNI type (1 byte)
                int hostnameLen = readUint16(data, pos + 3);
                int hostnameStart = pos + 5;

                if (hostnameStart + hostnameLen > offset + length)
                    return Optional.empty();

                // Extract the hostname string
                String hostname = new String(data, hostnameStart, hostnameLen);
                return Optional.of(hostname);
            }

            pos += extLen;  // Skip this extension, try next one
        }

        return Optional.empty();  // No SNI extension found
    }

    // ── Map SNI hostname to AppType ───────────────────────────────────────────
    public static AppType classifyBySNI(String sni) {
        if (sni == null || sni.isEmpty()) return AppType.UNKNOWN;
        String s = sni.toLowerCase();

        if (s.contains("youtube") || s.contains("googlevideo"))
            return AppType.YOUTUBE;
        if (s.contains("facebook") || s.contains("fbcdn"))
            return AppType.FACEBOOK;
        if (s.contains("instagram"))
            return AppType.INSTAGRAM;
        if (s.contains("twitter") || s.contains("twimg"))
            return AppType.TWITTER;
        if (s.contains("netflix"))
            return AppType.NETFLIX;
        if (s.contains("github"))
            return AppType.GITHUB;
        if (s.contains("whatsapp"))
            return AppType.WHATSAPP;
        if (s.contains("google"))
            return AppType.GOOGLE;
        if (s.contains("amazon") || s.contains("aws"))
            return AppType.UNKNOWN;

        return AppType.HTTPS;  // HTTPS but unknown app
    }

    // ── Helper: read 2 bytes as unsigned big-endian int ───────────────────────
    private static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}