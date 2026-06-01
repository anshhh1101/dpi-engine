package com.dpi.engine;

import java.util.HashSet;
import java.util.Set;

import com.dpi.model.AppType;

public class RuleEngine {

    // Three types of blocking rules — all O(1) lookup using HashSet
    private final Set<String>  blockedIps     = new HashSet<>();
    private final Set<AppType> blockedApps    = new HashSet<>();
    private final Set<String>  blockedDomains = new HashSet<>();

    // ── Add rules ─────────────────────────────────────────────────────────────

    public void blockIp(String ip) {
        blockedIps.add(ip);
        System.out.println("[Rules] Blocking IP     : " + ip);
    }

    public void blockApp(AppType app) {
        blockedApps.add(app);
        System.out.println("[Rules] Blocking App    : " + app);
    }

    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        System.out.println("[Rules] Blocking Domain : " + domain);
    }

    // ── Check if a flow should be blocked ────────────────────────────────────
    // Returns true if ANY rule matches — checked in order: IP → App → Domain
    public boolean isBlocked(String srcIp, AppType appType, String sni) {

        // Rule 1: Is the source IP blacklisted?
        if (blockedIps.contains(srcIp)) return true;

        // Rule 2: Is the application type blacklisted?
        if (appType != null && blockedApps.contains(appType)) return true;

        // Rule 3: Does the SNI contain a blocked domain substring?
        if (sni != null && !sni.isEmpty()) {
            String sniLower = sni.toLowerCase();
            for (String blocked : blockedDomains) {
                if (sniLower.contains(blocked)) return true;
            }
        }

        return false;
    }

    // ── Getters ───────────────────────────────────────────────────────────────

    public boolean hasRules() {
        return !blockedIps.isEmpty()
            || !blockedApps.isEmpty()
            || !blockedDomains.isEmpty();
    }

    public int getRuleCount() {
        return blockedIps.size() + blockedApps.size() + blockedDomains.size();
    }
}