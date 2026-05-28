package com.dpi.pcap;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Optional;

import com.dpi.model.RawPacket;

public class PcapReader {

    private DataInputStream dis;
    private boolean littleEndian;
    private boolean opened = false;

    public void open(String filename) throws IOException {
        dis = new DataInputStream(
                new BufferedInputStream(new FileInputStream(filename)));

        byte[] magic = new byte[4];
        dis.readFully(magic);

        int b0 = magic[0] & 0xFF;
        int b1 = magic[1] & 0xFF;
        int b2 = magic[2] & 0xFF;
        int b3 = magic[3] & 0xFF;

        if (b0 == 0xd4 && b1 == 0xc3 && b2 == 0xb2 && b3 == 0xa1) {
            littleEndian = true;
        } else if (b0 == 0xa1 && b1 == 0xb2 && b2 == 0xc3 && b3 == 0xd4) {
            littleEndian = false;
        } else {
            throw new IOException("Not a valid PCAP file.");
        }

        dis.skipBytes(20);
        opened = true;
        System.out.println("[PcapReader] File opened. Byte order: "
                + (littleEndian ? "little-endian" : "big-endian"));
    }

    public Optional<RawPacket> readNextPacket() throws IOException {
        if (!opened) throw new IllegalStateException("Call open() first");

        byte[] pktHeader = new byte[16];
        int bytesRead = dis.read(pktHeader, 0, 16);
        if (bytesRead == -1) return Optional.empty();
        if (bytesRead < 16)  return Optional.empty();

        long tsSec   = readUint32(pktHeader, 0);
        long tsUsec  = readUint32(pktHeader, 4);
        int  inclLen = (int) readUint32(pktHeader, 8);
        int  origLen = (int) readUint32(pktHeader, 12);

        if (inclLen > 65535 || inclLen < 0) {
            throw new IOException("Suspicious inclLen: " + inclLen);
        }

        byte[] data = new byte[inclLen];
        dis.readFully(data);

        RawPacket pkt = new RawPacket();
        pkt.timestampSec  = tsSec;
        pkt.timestampUsec = tsUsec;
        pkt.originalLen   = origLen;
        pkt.data          = data;

        return Optional.of(pkt);
    }

    public void close() {
        if (dis != null) {
            try { dis.close(); } catch (IOException ignored) {}
        }
        opened = false;
    }

    private long readUint32(byte[] buf, int offset) {
        ByteBuffer bb = ByteBuffer.wrap(buf, offset, 4);
        bb.order(littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
        return bb.getInt() & 0xFFFFFFFFL;
    }
}