import struct, socket, time

def write_uint32_le(val):
    return struct.pack('<I', val)

def make_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload=b'', proto=6):
    eth = bytes([0xaa,0xbb,0xcc,0xdd,0xee,0xff,
                 0x11,0x22,0x33,0x44,0x55,0x66,
                 0x08,0x00])
    total_len = 20 + 20 + len(payload)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    ip = struct.pack('>BBHHHBBH4s4s',
        0x45, 0, total_len, 0x0001, 0,
        64, proto, 0, src, dst)
    tcp = struct.pack('>HHIIBBHHH',
        src_port, dst_port, 1000, 0,
        0x50, 0x02, 8192, 0, 0)
    return eth + ip + tcp + payload

def make_tls_client_hello(sni_name):
    sni_bytes = sni_name.encode()
    sni_len = len(sni_bytes)

    # SNI extension
    sni_ext = (
        struct.pack('>HH', 0x0000, sni_len + 5) +  # ext type + ext len
        struct.pack('>H', sni_len + 3) +             # sni list len
        struct.pack('>BH', 0x00, sni_len) +          # sni type + sni len
        sni_bytes                                     # the actual domain
    )

    # Other extensions (just session ticket)
    other_ext = struct.pack('>HH', 0x0023, 0)

    extensions = sni_ext + other_ext
    ext_len = len(extensions)

    # Client Hello body
    random_bytes = bytes(32)
    session_id = b'\x00'
    cipher_suites = struct.pack('>HHH', 4, 0x002F, 0x0035)
    compression = b'\x01\x00'

    hello_body = (
        b'\x03\x03' +        # TLS version 1.2
        random_bytes +        # 32 random bytes
        session_id +          # session ID length = 0
        cipher_suites +       # 2 cipher suites
        compression +         # 1 compression method
        struct.pack('>H', ext_len) +
        extensions
    )

    # Handshake header
    handshake = (
        b'\x01' +                                      # Client Hello type
        struct.pack('>I', len(hello_body))[1:] +       # 3-byte length
        hello_body
    )

    # TLS record header
    tls_record = (
        b'\x16' +             # Content type: Handshake
        b'\x03\x01' +         # TLS version
        struct.pack('>H', len(handshake)) +
        handshake
    )

    return tls_record

# Build packets
packets = [
    # YouTube HTTPS with TLS Client Hello
    make_eth_ip_tcp("192.168.1.10", "142.250.185.46", 54321, 443,
                    make_tls_client_hello("www.youtube.com")),
    # Facebook HTTPS with TLS Client Hello
    make_eth_ip_tcp("192.168.1.10", "31.13.64.35", 54322, 443,
                    make_tls_client_hello("www.facebook.com")),
    # Google HTTPS with TLS Client Hello
    make_eth_ip_tcp("192.168.1.15", "142.250.185.100", 54323, 443,
                    make_tls_client_hello("www.google.com")),
    # Netflix HTTPS with TLS Client Hello
    make_eth_ip_tcp("192.168.1.20", "54.74.56.100", 54324, 443,
                    make_tls_client_hello("www.netflix.com")),
    # GitHub HTTPS with TLS Client Hello
    make_eth_ip_tcp("192.168.1.10", "140.82.121.4", 54325, 443,
                    make_tls_client_hello("github.com")),
    # DNS query (UDP, no SNI)
    make_eth_ip_tcp("192.168.1.20", "8.8.8.8", 12345, 53,
                    b'\x00\x01\x01\x00', proto=17),
    # HTTP (port 80, no TLS)
    make_eth_ip_tcp("192.168.1.30", "151.101.1.140", 54400, 80,
                    b'GET / HTTP/1.1\r\nHost: reddit.com\r\n\r\n'),
    # Second YouTube packet (same flow, data packet — no Client Hello)
    make_eth_ip_tcp("192.168.1.10", "142.250.185.46", 54321, 443,
                    b'\x17\x03\x03\x00\x20' + bytes(32)),
]

with open("test_dpi.pcap", "wb") as f:
    # Global header
    f.write(b'\xd4\xc3\xb2\xa1')
    f.write(write_uint32_le(0x00040002))
    f.write(write_uint32_le(0))
    f.write(write_uint32_le(0))
    f.write(write_uint32_le(65535))
    f.write(write_uint32_le(1))

    ts = int(time.time())
    for i, pkt in enumerate(packets):
        f.write(write_uint32_le(ts + i))
        f.write(write_uint32_le(0))
        f.write(write_uint32_le(len(pkt)))
        f.write(write_uint32_le(len(pkt)))
        f.write(pkt)

print(f"Created test_dpi.pcap with {len(packets)} packets")
print("SNI packets: youtube, facebook, google, netflix, github")