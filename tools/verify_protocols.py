"""额外的独立协议检查；原有的 117 项 Scapy 断言仍保留在 verify.py 中。"""
from pathlib import Path
import argparse
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--exe', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
options = parser.parse_args()
options.output.mkdir(parents=True, exist_ok=True)
expected = json.loads((ROOT / 'samples/plus/expected.json').read_text(encoding='utf-8'))
checks = []
for name, values in expected.items():
    output = options.output / (name + '.json')
    result = subprocess.run([str(options.exe), str(ROOT / 'samples/plus' / name), '--json', str(output)],
                            capture_output=True, text=True, check=True)
    data = json.loads(output.read_text(encoding='utf-8'))
    assert data['summary']['packets'] == values['frames']
    for key in ['completed', 'incomplete', 'overlaps']:
        assert data['summary']['ip_reassembly'][key] == values[key], (name, key, data['summary'])
        checks.append(name + ':' + key)
    if values['completed']:
        logical = [p['reassembled_datagram'] for p in data['packets'] if 'reassembled_datagram' in p]
        assert len(logical) == 2
        assert all(p['checksums']['transport']['status'] == 'verified' for p in logical)
        assert {p['ip_version'] for p in logical} == {4, 6}
        request = json.loads((ROOT / 'samples/expected.json').read_text(encoding='utf-8'))['request']
        assert any(stream['application'] == 'HTTP' and stream['direction_a'].endswith(request) for stream in data['streams'])
        checks.append('Scapy fragments independently decoded and HTTP recovered')
ng_manifest = ROOT / 'samples/plus/pcapng-expected.json'
if ng_manifest.exists():
    ng = json.loads(ng_manifest.read_text(encoding='utf-8'))
    for name, values in ng['valid'].items():
        target = options.output / (name + '.json')
        subprocess.run([str(options.exe), str(ROOT / 'samples/plus/pcapng_cases' / name), '--json', str(target)],
                       capture_output=True, text=True, check=True)
        data = json.loads(target.read_text(encoding='utf-8'))
        assert data['summary']['capture_format'] == 'pcapng'
        assert data['summary']['skipped_blocks'] == values['skipped']
        packets = data['packets']
        assert [p['timestamp_ns'] for p in packets] == values['times'], name
        assert [p['timestamp_available'] for p in packets] == values['available'], name
        assert [p['link_type'] for p in packets] == values['links'], name
        assert [p['interface_id'] for p in packets] == values['interfaces'], name
        assert [p['section_id'] for p in packets] == values['sections'], name
        if name in ['interface_isolation.pcapng', 'multi_section.pcapng']:
            assert data['summary']['flows'] == 2, name
        if name.startswith('showcase_'):
            assert data['summary']['packets'] == 22 and data['summary']['flows'] == 4
            assert data['streams'][0]['direction_a'] == json.loads((ROOT / 'samples/expected.json').read_text())['request']
        checks.append('PCAPNG:' + name)
    for name in ng['invalid']:
        result = subprocess.run([str(options.exe), str(ROOT / 'samples/plus/pcapng_cases' / name)], capture_output=True, text=True)
        assert result.returncode != 0 and 'PCAPNG' in result.stderr, (name, result.stdout, result.stderr)
        checks.append('Reject:' + name)
(options.output / 'validation.json').write_text(json.dumps({'status':'PASS', 'checks':checks}, indent=2), encoding='utf-8')
print('PASS', len(checks), 'additional independent checks')
