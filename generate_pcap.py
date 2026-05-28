import struct, socket, time

def write_uint32_le(val):
    return struct.pack('<I', val)

def make_packet(src_ip, dst_ip, src_port, dst_port, proto=6):
    eth = bytes([0xaa,0xbb,0xcc,0xdd,0xee,0xff,
                 0x11,0x22,0x33,0x44,0x55,0x66,
                 0x08,0x00])
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    ip = bytes([0x45,0x00,0x00,0x28,0x00,0x01,
                0x00,0x00,0x40,proto,0x00,0x00]) + src + dst
    tcp = struct.pack('>HHIIBBHHH',
        src_port, dst_port, 1000, 0, 0x50, 0x02, 8192, 0, 0)
    return eth + ip + tcp

packets = [
    make_packet("192.168.1.10", "142.250.185.46", 54321, 443),
    make_packet("192.168.1.10", "31.13.64.35",    54322, 443),
    make_packet("192.168.1.20", "8.8.8.8",        12345, 53, proto=17),
    make_packet("192.168.1.10", "142.250.185.46", 54321, 443),
    make_packet("192.168.1.30", "151.101.1.140",  54400, 80),
]

with open("test_dpi.pcap", "wb") as f:
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