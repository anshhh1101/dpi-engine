package com.dpi.pcap;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class PcapWriter {

    private BufferedOutputStream bos;
    private boolean opened = false;

    public void open(String filename) throws IOException {
        bos = new BufferedOutputStream(new FileOutputStream(filename));

        // Write the 24-byte global header — must match input file format
        // Magic number for little-endian pcap
        writeUint32Le(0xd4c3b2a1L);
        // Version 2.4
        writeUint16Le(2);
        writeUint16Le(4);
        // Timezone offset (0 = UTC)
        writeUint32Le(0);
        // Timestamp accuracy (always 0)
        writeUint32Le(0);
        // Snaplen — max packet size
        writeUint32Le(65535);
        // Link type — 1 = Ethernet
        writeUint32Le(1);

        opened = true;
        System.out.println("[PcapWriter] Output file opened: " + filename);
    }

    // Write one packet to the output file
    public void writePacket(byte[] data, long tsSec, long tsUsec) throws IOException {
        if (!opened) throw new IllegalStateException("Call open() first");

        // Write 16-byte packet header
        writeUint32Le(tsSec);
        writeUint32Le(tsUsec);
        writeUint32Le(data.length);   // included length
        writeUint32Le(data.length);   // original length

        // Write packet data
        bos.write(data);
    }

    public void close() throws IOException {
        if (bos != null) {
            bos.flush();
            bos.close();
        }
        opened = false;
    }

    // ── Helpers: write little-endian values ──────────────────────────────────

    private void writeUint32Le(long val) throws IOException {
        bos.write((int)( val        & 0xFF));
        bos.write((int)((val >>  8) & 0xFF));
        bos.write((int)((val >> 16) & 0xFF));
        bos.write((int)((val >> 24) & 0xFF));
    }

    private void writeUint16Le(int val) throws IOException {
        bos.write( val       & 0xFF);
        bos.write((val >> 8) & 0xFF);
    }
}