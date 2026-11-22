"""Cross-check independently decoded packet fields with Scapy and run a measured benchmark."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
_CACHE = ROOT / 'tools' / '.cache' / 'python'
if _CACHE.exists():
    sys.path.insert(0, str(_CACHE))
import hashlib
import json
import platform
import subprocess
import time
import argparse
import psutil
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS

parser=argparse.ArgumentParser()
parser.add_argument('--exe',type=Path,default=ROOT/'build-native/flowlens_cli.exe')
parser.add_argument('--output',type=Path,default=ROOT/'output/verification')
options=parser.parse_args()
OUT=options.output
OUT.mkdir(parents=True,exist_ok=True)
exe=options.exe
def run(args):
    p=subprocess.run([str(exe),*map(str,args)],capture_output=True,text=True,check=True)
    return json.loads(p.stdout)
summary=run([ROOT/'samples/showcase.pcap','--json',OUT/'analysis.json'])
analysis=json.loads((OUT/'analysis.json').read_text())
oracle=json.loads((ROOT/'samples/expected.json').read_text())
reference=rdpcap(str(ROOT/'samples/showcase.pcap'))
checks=[]
def verify(name,condition):
    checks.append({'check':name,'passed':bool(condition)})
    if not condition:raise AssertionError(name)
verify('packet_count',len(reference)==len(analysis['packets'])==oracle['packets'])
for i,(ref,packet) in enumerate(zip(reference,analysis['packets'])):
    verify(f'frame_{i+1}_length',len(bytes(ref))==packet['captured_length']==packet['length'])
    layer=ref.getlayer(IP) or ref.getlayer(IPv6)
    if layer:
        verify(f'frame_{i+1}_source',layer.src==packet['source'])
        verify(f'frame_{i+1}_destination',layer.dst==packet['destination'])
    transport=ref.getlayer(TCP) or ref.getlayer(UDP)
    if transport:
        verify(f'frame_{i+1}_ports',transport.sport==packet['source_port'] and transport.dport==packet['destination_port'])
    if TCP in ref:
        verify(f'frame_{i+1}_tcp_fields',ref[TCP].seq==packet['sequence'] and ref[TCP].ack==packet['acknowledgment'] and int(ref[TCP].flags)==packet['tcp_flags'])
    if DNS in ref:
        verify(f'frame_{i+1}_dns',packet['protocol']=='DNS')
stream=analysis['streams'][0]
verify('HTTP_request_byte_exact',stream['direction_a']==oracle['request'])
verify('HTTP_response_byte_exact',stream['direction_b']==oracle['response'])
verify('HTTP_nonstandard_port',stream['application']=='HTTP' and ':18080' in stream['b'])
verify('TCP_connection_count',len(analysis['streams'])==oracle['tcp_streams'])
verify('port80_binary_not_HTTP',analysis['packets'][-1]['protocol']=='TCP')
filtered=run([ROOT/'samples/showcase.pcap','--filter','dns'])
verify('DNS_filter',filtered['matched']==oracle['dns_packets'])
for name in ['big_endian','nanoseconds','loopback','raw_ipv6','vlan','ipv6_extensions','ipv6_empty','chunked']:
    verify('fixture_'+name,run([ROOT/'samples'/f'{name}.pcap'])['warnings']==0)
invalid=subprocess.run([str(exe),str(ROOT/'samples/truncated_record.pcap')],capture_output=True)
verify('malformed_file_nonzero_exit',invalid.returncode!=0)

benchmark=[]
for iteration in range(3):
    started=time.perf_counter()
    p=subprocess.Popen([str(exe),str(ROOT/'samples/showcase.pcap'),'--repeat','5000'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    peak=0;proc=psutil.Process(p.pid)
    while p.poll() is None:
        try:peak=max(peak,proc.memory_info().rss)
        except psutil.Error:pass
        time.sleep(.01)
    stdout,stderr=p.communicate()
    if p.returncode:raise RuntimeError(stderr)
    metrics=json.loads(stdout)
    metrics.update({'iteration':iteration+1,'wall_seconds':time.perf_counter()-started,'sampled_peak_working_set_bytes':peak})
    benchmark.append(metrics)

result={'reference_decoder':'Scapy 2.8.0','checks':checks,'passed':len(checks),'failed':0,'summary':summary,'benchmark':benchmark,'benchmark_note':'110000 records per run, repeatedly decoding the same 22-packet synthetic PCAP. Offline throughput is not a live capture line-rate or loss measurement. Working-set peak is sampled every 10 ms.','machine':{'system':platform.platform(),'processor':platform.processor(),'logical_cpus':psutil.cpu_count(),'memory_bytes':psutil.virtual_memory().total},'fixture_sha256':hashlib.sha256((ROOT/'samples/showcase.pcap').read_bytes()).hexdigest()}
(OUT/'verification.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
print(json.dumps({'independent_checks':len(checks),'benchmark_pps':[round(x['packets_per_second']) for x in benchmark],'peak_MiB':[round(x['sampled_peak_working_set_bytes']/1048576,2) for x in benchmark]}))
