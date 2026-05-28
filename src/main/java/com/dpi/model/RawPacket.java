package com.dpi.model;

public class RawPacket {
    public long   timestampSec;
    public long   timestampUsec;
    public int    originalLen;
    public byte[] data;

    public String getTimestamp() {
        return timestampSec + "." + String.format("%06d", timestampUsec);
    }
}