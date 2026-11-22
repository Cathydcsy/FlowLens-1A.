from pathlib import Path
import socket
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def packet(src, dst, sport, dport, seq, ack, flags, payload=b"", window=8192):
    a, b = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 80, flags, window, 0, 0)
    pseudo = a + b + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 69, 0, 40 + len(payload), 1, 0, 64, 6, 0, a, b)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0200000000020200000000010800") + ip + tcp + payload


def build(path):
    packets = []
    def send(reverse, seq, ack, flags=16, payload=b"", window=8192, dns=False):
        client, server = "192.0.2.31", "198.51.100.41"
        sport, dport = (47000, 53) if dns else (46000, 8080)
        if reverse:
            client, server, sport, dport = server, client, dport, sport
        packets.append(packet(client, server, sport, dport, seq, ack, flags, payload, window))

    send(False, 1000, 0, 2)
    send(True, 9000, 1001, 18)
    send(False, 1001, 9001)
    request = b"GET /fixture HTTP/1.1\r\nHost: example.test\r\n\r\n"
    send(False, 1001, 9001, 24, request)
    # Same segment repeats three times, each counted at most once as retransmission.
    for _ in range(3):
        send(False, 1001, 9001, 24, request)
    send(True, 9001, 1001)
    for _ in range(3):
        send(True, 9001, 1001)
    send(True, 9001, 1001, window=0)
    # Deliberately reordered data and a reset, without any live network traffic.
    send(False, 1001 + len(request) + 10, 9001, 24, b"later")
    send(False, 1001 + len(request), 9001, 24, b"0123456789")
    send(False, 1001 + len(request) + 15, 9001, 20)

    send(False, 3000, 0, 2, dns=True)
    send(True, 7000, 3001, 18, dns=True)
    send(False, 3001, 7001, dns=True)
    question = b"\x07example\x04test\0" + struct.pack("!HH", 1, 1)
    # Two questions in one query message must still count as ONE DNS query.
    query = struct.pack("!6H", 0x1234, 0x0100, 2, 0, 0, 0) + question + question
    response = struct.pack("!6H", 0x1234, 0x8180, 0, 0, 0, 0)
    send(False, 3001, 7001, 24, struct.pack("!H", len(query)) + query, dns=True)
    send(True, 7001, 3001 + 2 + len(query), 24,
         struct.pack("!H", len(response)) + response, dns=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(packets):
            # The missing earlier segment arrives within 0.5 ms: Wireshark's
            # out-of-order timing heuristic can distinguish it from a retransmit.
            micros = 120500 if index == 13 else index * 10000
            stream.write(struct.pack("<IIII", 1700000000, micros, len(frame), len(frame)))
            stream.write(frame)
    return len(packets)


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "samples" / "anomalies_dns.pcap"
    print(f"{build(target)} synthetic packets -> {target}")
