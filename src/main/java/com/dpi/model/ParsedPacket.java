package com.dpi.model;

public class ParsedPacket {
    public String  srcMac;
    public String  dstMac;
    public int     etherType;

    public int     srcIp;
    public int     dstIp;
    public int     protocol;
    public int     ttl;
    public boolean isIPv4 = false;

    public int     srcPort;
    public int     dstPort;
    public boolean hasTcp = false;
    public boolean hasUdp = false;

    public byte[]  rawData;
    public int     payloadOffset;
    public int     payloadLength;
}