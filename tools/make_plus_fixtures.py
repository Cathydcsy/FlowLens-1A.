"""Generate only samples/plus fixtures; never rewrite the original course samples."""
from pathlib import Path
import json
import sys
import struct

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/.cache/python'))
from scapy.all import Ether, IP, IPv6, IPv6ExtHdrFragment, fragment, fragment6, rdpcap, wrpcap


def make_pcapng(directory, original):
    def block(kind, body, endian='<'):
        body += b'\0' * (-len(body) % 4)
        length = len(body) + 12
        return struct.pack(endian + 'II', kind, length) + body + struct.pack(endian + 'I', length)
    def option(code, data, endian='<'):
        return struct.pack(endian + 'HH', code, len(data)) + data + b'\0' * (-len(data) % 4)
    def shb(endian='<', length=-1):
        return block(0x0a0d0d0a, struct.pack(endian + 'IHHq', 0x1a2b3c4d, 1, 0, length), endian)
    def idb(link=1, resolution=6, offset=0, snaplen=65535, endian='<'):
        options = option(9, bytes([resolution]), endian) + option(14, struct.pack(endian + 'q', offset), endian) + b'\0' * 4
        return block(1, struct.pack(endian + 'HHI', link, 0, snaplen) + options, endian)
    def epb(data, ticks, interface=0, endian='<', obsolete=False):
        header = struct.pack(endian + ('HH' if obsolete else 'I'), interface, 0xffff) if obsolete else struct.pack(endian + 'I', interface)
        header += struct.pack(endian + 'IIII', ticks >> 32, ticks & 0xffffffff, len(data), len(data))
        return block(2 if obsolete else 6, header + data + b'\0' * (-len(data) % 4), endian)
    files, expected, invalid = {}, {}, {}
    data = bytes(original[0]); raw6 = bytes(original[16][IPv6])
    def valid(name, content, times, links=None, interfaces=None, sections=None, available=None, skipped=0):
        files[name] = content
        count = len(times)
        expected[name] = dict(times=times, links=links or [1] * count,
            interfaces=interfaces or [0] * count, sections=sections or [0] * count,
            available=available or [True] * count, skipped=skipped)
    for endian, label in [('<', 'little'), ('>', 'big')]:
        times = [int(packet.time * 1000000000) for packet in original]
        content = shb(endian) + idb(resolution=9, endian=endian)
        content += b''.join(epb(bytes(packet), time, endian=endian) for packet, time in zip(original, times))
        valid('showcase_' + label + '.pcapng', content, times)
    valid('multi_interface.pcapng', shb() + idb() + idb(link=101, resolution=9) + epb(data, 1000) + epb(raw6, 2000000, 1),
          [1000000, 2000000], [1, 101], [0, 1])
    valid('interface_isolation.pcapng', shb() + idb() + idb() + epb(data, 1) + epb(data, 2, 1), [1000, 2000], interfaces=[0, 1])
    valid('multi_section.pcapng', shb() + idb() + epb(data, 1000) + shb('>') + idb(endian='>') + epb(data, 2000, endian='>'),
          [1000000, 2000000], sections=[0, 1])
    valid('binary_resolution.pcapng', shb() + idb(resolution=0x80 | 10, offset=1) + epb(data, 2560), [3500000000])
    valid('binary_63.pcapng', shb() + idb(resolution=0x80 | 63) + epb(data, 2**64 - 1), [1999999999])
    valid('binary_127.pcapng', shb() + idb(resolution=255) + epb(data, 2**64 - 1), [0])
    valid('decimal_subnanosecond.pcapng', shb() + idb(resolution=12) + epb(data, 1234567890123), [1234567890])
    valid('decimal_127.pcapng', shb() + idb(resolution=127) + epb(data, 2**64 - 1), [0])
    valid('negative_offset.pcapng', shb() + idb(offset=-1) + epb(data, 2500000), [1500000000])
    valid('obsolete_packet.pcapng', shb() + idb() + epb(data, 2500000, obsolete=True), [2500000000])
    valid('simple_packet.pcapng', shb() + idb() + block(3, struct.pack('<I', len(data)) + data), [0], available=[False])
    valid('simple_truncated.pcapng', shb() + idb(snaplen=16) + block(3, struct.pack('<I', len(data)) + data[:16]), [0], available=[False])
    valid('unlimited_snapshot.pcapng', shb() + idb(snaplen=0) + epb(data, 1), [1000])
    ancillary = block(0xabcdef, b'abcdefgh')
    valid('ancillary_block.pcapng', shb() + idb() + ancillary + epb(data, 1), [1000], skipped=1)
    section_body = idb() + epb(data, 1)
    valid('known_section_length.pcapng', shb(length=len(section_body)) + section_body, [1000])
    prefix = shb() + idb()
    invalid['bad_trailer.pcapng'] = prefix + epb(data, 1)[:-4] + struct.pack('<I', 12)
    invalid['truncated_block.pcapng'] = prefix + epb(data, 1)[:-5]
    invalid['partial_header.pcapng'] = prefix + b'\x06\0'
    invalid['unknown_interface.pcapng'] = prefix + epb(data, 1, 7)
    invalid['missing_idb.pcapng'] = shb() + epb(data, 1)
    bad = bytearray(epb(data, 1)); struct.pack_into('<I', bad, 20, len(data) + 5)
    invalid['captured_above_original.pcapng'] = prefix + bad
    invalid['snaplen_exceeded.pcapng'] = shb() + idb(snaplen=16) + epb(data, 1)
    invalid['bad_bom.pcapng'] = shb()[:8] + b'abcd' + shb()[12:]
    bad = bytearray(shb()); struct.pack_into('<H', bad, 12, 2)
    invalid['unsupported_version.pcapng'] = bad
    invalid['huge_block.pcapng'] = struct.pack('<III', 0x0a0d0d0a, 64 * 1024 * 1024, 0x1a2b3c4d)
    invalid['unaligned_block.pcapng'] = prefix + struct.pack('<II', 6, 13) + b'\0' * 5
    invalid['short_block.pcapng'] = prefix + struct.pack('<II', 6, 8)
    invalid['short_packet_data.pcapng'] = prefix + block(6, struct.pack('<5I', 0, 0, 1, 1000, 1000))
    invalid['bad_option_length.pcapng'] = shb() + block(1, struct.pack('<HHIHH', 1, 0, 65535, 9, 100))
    invalid['bad_tsresol_size.pcapng'] = shb() + block(1, struct.pack('<HHI', 1, 0, 65535) + option(9, b'xx'))
    invalid['duplicate_tsresol.pcapng'] = shb() + block(1, struct.pack('<HHI', 1, 0, 65535) + option(9, b'\x06') * 2)
    invalid['early_end_of_options.pcapng'] = shb() + block(1, struct.pack('<HHI', 1, 0, 65535) + b'\0' * 8)
    invalid['section_length_short.pcapng'] = shb(length=4) + section_body
    invalid['section_length_truncated.pcapng'] = shb(length=len(section_body) + 4) + section_body
    invalid['section_negative_length.pcapng'] = shb(length=-2)
    invalid['timestamp_overflow.pcapng'] = shb() + idb(resolution=0) + epb(data, 2**64 - 1)
    invalid['binary_timestamp_overflow.pcapng'] = shb() + idb(resolution=128) + epb(data, 2**64 - 1)
    invalid['timestamp_underflow.pcapng'] = shb() + idb(offset=-1) + epb(data, 0)
    invalid['timestamp_offset_overflow.pcapng'] = shb() + idb(offset=-2**63) + epb(data, 0)
    invalid['simple_extra_data.pcapng'] = shb() + idb() + block(3, struct.pack('<I', 4) + b'12345678')
    target = directory / 'pcapng_cases'; target.mkdir(exist_ok=True)
    for name, content in {**files, **invalid}.items():
        (target / name).write_bytes(content)
    (directory / 'pcapng-expected.json').write_text(json.dumps(dict(valid=expected, invalid=list(invalid)), indent=2), encoding='utf-8')


def main():
    directory = ROOT / 'samples/plus'
    directory.mkdir(exist_ok=True)
    original = rdpcap(str(ROOT / 'samples/showcase.pcap'))
    v4 = [Ether(src=original[21].src, dst=original[21].dst) / part
          for part in fragment(original[21][IP], fragsize=24)]
    ip6 = original[16][IPv6]
    fragmented6 = IPv6(src=ip6.src, dst=ip6.dst) / IPv6ExtHdrFragment(id=0x12345678) / ip6.payload
    v6 = [Ether(src=original[16].src, dst=original[16].dst) / part for part in fragment6(fragmented6, 72)]
    fixtures = {
        'fragments_out_of_order.pcap': list(reversed(v4)) + list(reversed(v6)),
        'fragment_incomplete.pcap': [v4[0]],
        'fragment_overlap.pcap': [v4[0], v4[1].copy(), v4[-1]],
    }
    fixtures['fragment_overlap.pcap'][1][IP].frag = 1
    fixtures['fragment_overlap.pcap'][1][IP].chksum = None
    expected = {
        'fragments_out_of_order.pcap': {'completed': 2, 'incomplete': 0, 'overlaps': 0},
        'fragment_incomplete.pcap': {'completed': 0, 'incomplete': 1, 'overlaps': 0},
        'fragment_overlap.pcap': {'completed': 0, 'incomplete': 0, 'overlaps': 1},
    }
    for name, packets in fixtures.items():
        for index, packet in enumerate(packets):
            packet.time = 1700000000 + index / 1000
        wrpcap(str(directory / name), packets)
        expected[name]['frames'] = len(packets)
    (directory / 'expected.json').write_text(json.dumps(expected, indent=2), encoding='utf-8')
    make_pcapng(directory, original)
    print('Generated', len(fixtures), 'Scapy fragment fixtures in samples/plus')


if __name__ == '__main__':
    main()
