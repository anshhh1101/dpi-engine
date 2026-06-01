package com.dpi;

import java.util.ArrayList;
import java.util.List;

import com.dpi.engine.DpiEngine;
import com.dpi.model.AppType;

public class Main {

    public static void main(String[] args) throws Exception {

        String inputFile  = "test_dpi.pcap";
        String outputFile = "output.pcap";
        DpiEngine engine  = new DpiEngine();

        // Collect positional args (not starting with --)
        List<String> positional = new ArrayList<>();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--block-app" -> {
                    if (i + 1 < args.length)
                        engine.blockApp(AppType.valueOf(args[++i].toUpperCase()));
                }
                case "--block-ip" -> {
                    if (i + 1 < args.length)
                        engine.blockIp(args[++i]);
                }
                case "--block-domain" -> {
                    if (i + 1 < args.length)
                        engine.blockDomain(args[++i]);
                }
                default -> {
                    if (!args[i].startsWith("--"))
                        positional.add(args[i]);
                }
            }
        }

        // First positional = input, second positional = output
        if (positional.size() >= 1) inputFile  = positional.get(0);
        if (positional.size() >= 2) outputFile = positional.get(1);

        System.out.println("=================================================");
        System.out.println("         DPI ENGINE v1.0 - Java                  ");
        System.out.println("=================================================");
        System.out.println("  Input  : " + inputFile);
        System.out.println("  Output : " + outputFile);
        System.out.println("=================================================");

        engine.process(inputFile, outputFile);
        engine.printReport();
    }
}