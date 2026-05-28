package com.dpi.model;

public class Flow {
    public FiveTuple tuple;
    public String    sni         = "";
    public AppType   appType     = AppType.UNKNOWN;
    public boolean   blocked     = false;
    public int       packetCount = 0;
    public long      byteCount   = 0;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
    }

    @Override
    public String toString() {
        return String.format("Flow[%s | app=%-12s | pkts=%3d | bytes=%5d | sni=%s]",
            tuple, appType, packetCount, byteCount,
            sni.isEmpty() ? "-" : sni);
    }
}