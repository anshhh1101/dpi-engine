package com.dpi.inspector;

import java.util.Optional;

public class HTTPExtractor {

    // Extract the Host header value from an HTTP request
    // Example: "GET / HTTP/1.1\r\nHost: www.reddit.com\r\n" → "www.reddit.com"
    public static Optional<String> extractHost(byte[] data, int offset, int length) {

        if (length < 4) return Optional.empty();

        // Convert payload to string for easy searching
        // HTTP headers are always ASCII
        String payload;
        try {
            payload = new String(data, offset, length, "ASCII");
        } catch (Exception e) {
            return Optional.empty();
        }

        // Must start with an HTTP method
        if (!payload.startsWith("GET ")    &&
            !payload.startsWith("POST ")   &&
            !payload.startsWith("PUT ")    &&
            !payload.startsWith("DELETE ") &&
            !payload.startsWith("HEAD ")   &&
            !payload.startsWith("OPTIONS ")) {
            return Optional.empty();
        }

        // Search for "Host:" header (case-insensitive)
        String payloadLower = payload.toLowerCase();
        int hostIdx = payloadLower.indexOf("\r\nhost:");
        if (hostIdx == -1) {
            hostIdx = payloadLower.indexOf("\nhost:");
        }
        if (hostIdx == -1) return Optional.empty();

        // Skip past "\r\nHost: " or "\nHost: "
        int valueStart = payload.indexOf(':', hostIdx) + 1;

        // Skip whitespace
        while (valueStart < payload.length()
               && payload.charAt(valueStart) == ' ') {
            valueStart++;
        }

        // Read until end of line
        int valueEnd = payload.indexOf('\r', valueStart);
        if (valueEnd == -1) valueEnd = payload.indexOf('\n', valueStart);
        if (valueEnd == -1) valueEnd = payload.length();

        String host = payload.substring(valueStart, valueEnd).trim();
        if (host.isEmpty()) return Optional.empty();

        return Optional.of(host);
    }
}