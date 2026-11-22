"""生成确定性的实验流量，不访问外部网络。"""
import json
import ipaddress
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'samples'
OUT.mkdir(exist_ok=True)
def checksum(b):
    if len(b)%2:b+=b'\0'
    n=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while n>>16:n=(n&65535)+(n>>16)
    return (~n)&65535
def ip4(s,d,p,payload,frag=0,options=b''):
    h=struct.pack('!BBHHHBBH4s4s',0x45+len(options)//4,0,20+len(options)+len(payload),731,frag,64,p,0,ipaddress.ip_address(s).packed,ipaddress.ip_address(d).packed)+options
    h=h[:10]+struct.pack('!H',checksum(h))+h[12:]
    return h+payload
def ip6(s,d,p,payload):return struct.pack('!IHBB16s16s',6<<28,len(payload),p,64,ipaddress.ip_address(s).packed,ipaddress.ip_address(d).packed)+payload
def eth(payload,type=0x800,vlan=False):
    b=bytes.fromhex('020000000002020000000001')
    return b+(struct.pack('!HHH',0x8100,7,type) if vlan else struct.pack('!H',type))+payload
def tcp(s,d,sp,dp,seq,ack,flags,data=b'',v6=False,options=b''):
    h=struct.pack('!HHIIBBHHH',sp,dp,seq&0xffffffff,ack&0xffffffff,(5+len(options)//4)<<4,flags,64240,0,0)+options+data
    a,b=ipaddress.ip_address(s).packed,ipaddress.ip_address(d).packed
    pseudo=a+b+(struct.pack('!I3xB',len(h),6) if v6 else struct.pack('!BBH',0,6,len(h)))
    h=h[:16]+struct.pack('!H',checksum(pseudo+h))+h[18:]
    return eth(ip6(s,d,6,h) if v6 else ip4(s,d,6,h),0x86dd if v6 else 0x800)
def udp(s,d,sp,dp,data,v6=False):
    h=struct.pack('!HHHH',sp,dp,8+len(data),0)+data
    a,b=ipaddress.ip_address(s).packed,ipaddress.ip_address(d).packed
    pseudo=a+b+(struct.pack('!I3xB',len(h),17) if v6 else struct.pack('!BBH',0,17,len(h)))
    c=checksum(pseudo+h) or 0xffff
    h=h[:6]+struct.pack('!H',c)+h[8:]
    return eth(ip6(s,d,17,h) if v6 else ip4(s,d,17,h),0x86dd if v6 else 0x800)
def pcap(path,frames,link=1,endian='<',nano=False):
    magic=0xa1b23c4d if nano else 0xa1b2c3d4
    with path.open('wb') as f:
        f.write(struct.pack(endian+'IHHIIII',magic,2,4,0,0,65535,link))
        for i,frame in enumerate(frames):
            f.write(struct.pack(endian+'IIII',1794268800, i*(1000000 if nano else 1000),len(frame),len(frame)))
            f.write(frame)
    return path

A,B='192.0.2.10','198.51.100.20'
req=b'GET /lab?course=security HTTP/1.1\r\nHost: lab.example\r\nUser-Agent: FlowLens-fixture\r\nContent-Length: 0\r\n\r\n'
resp=b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nHello from FlowLens!'
frames=[tcp(A,B,51000,18080,1000,0,2),tcp(B,A,18080,51000,5000,1001,18),tcp(A,B,51000,18080,1001,5001,16)]
# 先收到后一段，再补齐缺口，最后制造一次完全重复的重传。
cut=29
frames += [tcp(A,B,51000,18080,1001+cut,5001,24,req[cut:]),tcp(A,B,51000,18080,1001,5001,24,req[:cut]),tcp(A,B,51000,18080,1001,5001,24,req[:cut])]
frames += [tcp(B,A,18080,51000,5001,1001+len(req),24,resp[:37]),tcp(B,A,18080,51000,5038,1001+len(req),24,resp[37:]),tcp(A,B,51000,18080,1001+len(req),5001+len(resp),17),tcp(B,A,18080,51000,5001+len(resp),1002+len(req),17)]
name=b'\x03lab\x07example\x00'
query=struct.pack('!HHHHHH',0x7130,0x0100,1,0,0,0)+name+struct.pack('!HH',1,1)
answer=struct.pack('!HHHHHH',0x7130,0x8180,1,1,0,0)+name+struct.pack('!HH',1,1)+b'\xc0\x0c'+struct.pack('!HHIH',1,1,300,4)+ipaddress.ip_address(B).packed
frames += [udp(A,'192.0.2.53',54000,53,query),udp('192.0.2.53',A,53,54000,answer)]
ic=struct.pack('!BBHHH',8,0,0,123,1)+b'flowlens';ic=ic[:2]+struct.pack('!H',checksum(ic))+ic[4:]
frames += [eth(ip4(A,B,1,ic))]
arp=struct.pack('!HHBBH',1,0x800,6,4,1)+bytes.fromhex('020000000001')+ipaddress.ip_address(A).packed+b'\0'*6+ipaddress.ip_address('192.0.2.1').packed
frames += [eth(arp,0x806)]
V6A,V6B='2001:db8::10','2001:db8::20'
frames += [tcp(V6A,V6B,52000,18080,8000,0,2,v6=True),tcp(V6B,V6A,18080,52000,9000,8001,18,v6=True),tcp(V6A,V6B,52000,18080,8001,9001,24,req,v6=True)]
echo=struct.pack('!BBHHH',128,0,0,77,1)+b'v6';pseudo=ipaddress.ip_address(V6A).packed+ipaddress.ip_address(V6B).packed+struct.pack('!I3xB',len(echo),58);echo=echo[:2]+struct.pack('!H',checksum(pseudo+echo))+echo[4:]
frames += [eth(ip6(V6A,V6B,58,echo),0x86dd)]
tls=b'\x17\x03\x03\x00\x10'+bytes(range(16))
frames += [tcp(A,B,53000,443,4000,0,2),tcp(A,B,53000,443,4001,0,24,tls)]
frames += [udp(A,B,55000,9000,b'ordinary UDP payload')]
frames += [tcp(A,B,56000,80,6000,0,24,b'This is not an HTTP message.\r\n')]
pcap(OUT/'showcase.pcap',frames)
pcap(OUT/'big_endian.pcap',frames[:3],endian='>')
pcap(OUT/'nanoseconds.pcap',frames[:3],nano=True)
pcap(OUT/'loopback.pcap',[struct.pack('<I',2)+frames[0][14:]],link=0)
pcap(OUT/'raw_ipv6.pcap',[frames[14][14:]],link=101)
pcap(OUT/'ipv6_empty.pcap',[eth(ip6(V6A,V6B,59,b''),0x86dd)])
pcap(OUT/'vlan.pcap',[frames[0][:12]+struct.pack('!HHH',0x8100,7,0x800)+frames[0][14:]])
# 构造 UDP 前的 IPv6 扩展头和原子分片。
u=udp(V6A,V6B,54000,53,query,v6=True)[54:]
pcap(OUT/'ipv6_extensions.pcap',[eth(ip6(V6A,V6B,0,bytes([17,0])+b'\0'*6+u),0x86dd),eth(ip6(V6A,V6B,44,bytes([17,0])+b'\0'*6+u),0x86dd)])
bad=[b'\0'*8,eth(ip4(A,B,6,b'\0'*5)),eth(ip4(A,B,17,b'\0'*8)),eth(ip4(A,B,6,b'\0'*20,frag=0x2000)),udp(A,B,53000,53,struct.pack('!HHHHHH',1,0x100,1,0,0,0)+b'\xc0\x0c\0\1\0\1')]
pcap(OUT/'edge_cases.pcap',bad)
# 构造正确的 HTTP 分块传输和 TCP 序号回绕。
chunk=b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n world\r\n0\r\n\r\n'
pcap(OUT/'chunked.pcap',[tcp(A,B,18080,57000,0xfffffff0,0,2),tcp(A,B,18080,57000,0xfffffff1,0,24,chunk[:20]),tcp(A,B,18080,57000,0xfffffff1+20,0,24,chunk[20:])])
pcap(OUT/'truncated_record.pcap',frames[:1]);p=OUT/'truncated_record.pcap';p.write_bytes(p.read_bytes()[:-4])
oracle={'description':'Synthetic documentation address space only; expected values are defined before analysis.','packets':len(frames),'request':req.decode(),'response':resp.decode(),'tcp_streams':4,'dns_packets':2,'nonstandard_http_port':18080,'retransmitted_bytes':cut,'source':A,'destination':B}
(OUT/'expected.json').write_text(json.dumps(oracle,indent=2),encoding='utf-8')
print(json.dumps({'fixtures':len(list(OUT.glob('*.pcap'))),'showcase_packets':len(frames)}))
