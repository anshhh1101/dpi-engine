# DPI Engine — Deep Packet Inspection in Java

A packet-level network traffic analyser built from scratch in Java.
Reads real `.pcap` files, inspects TLS/HTTP application layer data,
classifies traffic by application, and blocks based on rules.

**GitHub:** github.com/anshhh1101/dpi-engine  
**Built for:** Cisco recruitment drive — demonstrates L2–L7 protocol knowledge

---

## What it does

```
input.pcap → [Ethernet parser] → [IP parser] → [TCP parser]
                                                      ↓
                                            [TLS SNI extractor]
                                            [HTTP Host extractor]
                                                      ↓
                                            [Flow tracker]  ← HashMap<FiveTuple, Flow>
                                                      ↓
                                            [Rule engine]   ← block by IP/App/Domain
                                                      ↓
                                            output.pcap + stats report
```

---

## Architecture

| Class | Package | Purpose |
|---|---|---|
| `PcapReader` | `pcap` | Reads binary `.pcap` files using `DataInputStream` |
| `PcapWriter` | `pcap` | Writes filtered packets to output `.pcap` |
| `PacketParser` | `parser` | Parses Ethernet → IP → TCP/UDP headers from raw bytes |
| `SNIExtractor` | `inspector` | Navigates TLS Client Hello to extract SNI hostname |
| `HTTPExtractor` | `inspector` | Extracts `Host:` header from HTTP requests |
| `FlowTracker` | `engine` | `HashMap<FiveTuple, Flow>` — O(1) flow state lookup |
| `RuleEngine` | `engine` | Blocks traffic by IP, AppType, or domain substring |
| `DpiEngine` | `engine` | Orchestrates the full pipeline |

---

## Key Concepts

**Five-Tuple Flow Tracking**  
Every TCP/UDP connection is uniquely identified by:
`(srcIP, dstIP, srcPort, dstPort, protocol)`  
Implemented as a Java `record` — auto-generates `equals()` and `hashCode()`
for use as a `HashMap` key with O(1) lookup per packet.

**SNI Extraction**  
Even HTTPS traffic leaks the destination domain in the TLS Client Hello
(sent before encryption begins). The SNI field at extension type `0x0000`
contains the hostname in plaintext — this is how Cisco Firepower identifies
application traffic without decrypting it.

**Flow-Based Blocking**  
Once a flow is identified (e.g. YouTube via SNI), all subsequent packets
of that TCP connection are dropped without re-inspection.

---

## Build & Run

**Prerequisites:** Java 17+, Maven 3.x

```bash
# Generate test traffic
python generate_pcap.py

# Build
mvn package -q

# Run — no blocking
java -jar target/dpi-engine.jar input.pcap output.pcap

# Block YouTube
java -jar target/dpi-engine.jar input.pcap output.pcap --block-app YOUTUBE

# Block by IP
java -jar target/dpi-engine.jar input.pcap output.pcap --block-ip 192.168.1.10

# Block by domain substring
java -jar target/dpi-engine.jar input.pcap output.pcap --block-domain facebook

# Multiple rules
java -jar target/dpi-engine.jar input.pcap output.pcap \
  --block-app YOUTUBE --block-domain facebook
```

---

## Sample Output

```
====================================================
             DPI ENGINE - FINAL REPORT
====================================================
  Total Packets        : 8
  Total Bytes          : 914 bytes
  Forwarded            : 5
  Dropped              : 3
====================================================
               APPLICATION BREAKDOWN
====================================================
  YOUTUBE        2   25.0%  #####          [BLOCKED]
  FACEBOOK       1   12.5%  ##             [BLOCKED]
  NETFLIX        1   12.5%  ##
  GOOGLE         1   12.5%  ##
  GITHUB         1   12.5%  ##
====================================================
               DETECTED DOMAINS
====================================================
  github.com                       GITHUB
  reddit.com                       HTTP
  www.facebook.com                 FACEBOOK   [BLOCKED]
  www.youtube.com                  YOUTUBE    [BLOCKED]
====================================================
```

---

## Supported AppTypes

`YOUTUBE` `FACEBOOK` `INSTAGRAM` `TWITTER` `NETFLIX`
`GITHUB` `WHATSAPP` `GOOGLE` `HTTP` `HTTPS` `DNS` `UNKNOWN`

---

## Blocking Rules

| Rule | Flag | Example |
|---|---|---|
| Source IP | `--block-ip` | `--block-ip 192.168.1.50` |
| Application | `--block-app` | `--block-app YOUTUBE` |
| Domain substring | `--block-domain` | `--block-domain tiktok` |

Rules are checked in order: IP → AppType → Domain. First match wins.

---

## Extending

Add new app signatures in `SNIExtractor.java`:
```java
if (s.contains("tiktok")) return AppType.TIKTOK;
```

Add new AppType in `AppType.java`:
```java
TIKTOK,
```