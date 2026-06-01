package com.dpi;

import com.dpi.engine.DpiEngine;

public class Main {

    public static void main(String[] args) throws Exception {

        String inputFile = args.length > 0 ? args[0] : "test_dpi.pcap";

        System.out.println("╔══════════════════════════════════════════════════╗");
        System.out.println("║           DPI ENGINE v1.0 — Java                 ║");
        System.out.println("╚══════════════════════════════════════════════════╝");
        System.out.println("Processing: " + inputFile);

        DpiEngine engine = new DpiEngine();
        engine.process(inputFile);
        engine.printReport();
    }
}