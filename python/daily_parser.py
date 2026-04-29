#!/usr/bin/env python3


import sys, os, json, csv, gzip, struct, socket, pickle, tarfile, argparse, time
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import dpkt
except ImportError:
    print("ERROR: pip install dpkt"); sys.exit(1)

try:
    import geoip2.database
    _MM_BASE = os.path.join(os.path.expanduser('~'), 'ibr-analyst', 'lib', 'maxmind')
    MAXMIND_COUNTRY = os.path.join(_MM_BASE, 'GeoLite2-Country.mmdb')
    MAXMIND_ASN = os.path.join(_MM_BASE, 'GeoLite2-ASN.mmdb')
    GEOIP_AVAILABLE = os.path.exists(MAXMIND_COUNTRY)
    ASN_AVAILABLE   = os.path.exists(MAXMIND_ASN)
    if not GEOIP_AVAILABLE: print("Warning: GeoLite2-Country.mmdb not found")
    if not ASN_AVAILABLE:print("Warning: GeoLite2-ASN.mmdb not found")
except ImportError:
    print("Warning: geoip2 not available  pip install geoip2 ")
    GEOIP_AVAILABLE = False
    ASN_AVAILABLE = False

BASE = os.path.join(os.path.expanduser('~'), 'ibr-analyst')


ALL_SIGS = ['mirai','hajime','hajime_type1','atk01','atk02','atk03',
            'atk04','atk05','atk06','masscan','zmap','surv01','surv02']

def fingerprint(ip, tcp):
    m = set()
    if not (tcp.flags & dpkt.tcp.TH_SYN) or (tcp.flags & dpkt.tcp.TH_ACK):
        return m
    try:
        d = struct.unpack('>I', ip.dst)[0]
    except:
        return m
    if d == tcp.seq: m.add('mirai')
    if tcp.win == 14600: m.add('hajime')
    if (tcp.seq >> 16) == 0 or (tcp.seq & 0xFFFF) == 0: m.add('hajime_type1')
    if tcp.win == 29040: m.add('atk01')
    if tcp.win == 14520: m.add('atk02')
    if (d ^ tcp.seq) == 32322235778 and tcp.win == 1300: m.add('atk03')
    if tcp.seq == 2018915346: m.add('atk04')
    if tcp.seq == 333994513: m.add('atk05')
    if tcp.seq == 30000 and tcp.win == 65535: m.add('atk06')
    if (d ^ tcp.dport ^ ip.id ^ tcp.seq) == 0: m.add('masscan')
    if ip.id == 54321: m.add('zmap')
    if tcp.win == 0: m.add('surv01')
    if tcp.seq == 100 and ip.id == 123 and tcp.win == 1024: m.add('surv02')
    return m


class IBRParser:

    def __init__(self, date_str, hourly=False, detailed=False):
        self.date_str = date_str
        self.hourly = hourly
        self.detailed = detailed
        self.t_start = time.time()

        #Basic
        self.total_packets = 0
        self.total_bytes = 0
        self.first_ts = None
        self.last_ts = None
        self.file_size_bytes = 0

        #Protocol bytes
        self.proto_pkts = Counter()
        self.proto_bytes = Counter()

        #TCP flags
        self.flag_counts = Counter()

         #Port counters
        self.tcp_dst_pkts = Counter()
        self.tcp_dst_bytes = Counter()
        self.tcp_dst_ips = defaultdict(set)
        self.udp_dst_pkts = Counter()
        self.udp_dst_bytes = Counter()
        self.udp_dst_ips = defaultdict(set)

        #ICMP 
        self.icmp_type_code_pkts = Counter()
        self.icmp_type_code_bytes = Counter()
        self.icmp_type_code_ips = defaultdict(set)

        #Source IPs
        self.src_ip_set = set()
        self.ip_pkts = Counter()
        self.ip_bytes = Counter()
        self.ip_proto = defaultdict(Counter)       
        self.ip_dst_ports= defaultdict(set)           
        self.ip_dst_ips = defaultdict(set)       
        self.unique_src_ports_set = set()

        #Country / ASN
        self.cc_pkts = Counter()
        self.cc_bytes = Counter()
        self.cc_ips = defaultdict(set)
        self.asn_pkts = Counter()
        self.asn_bytes = Counter()
        self.asn_ips = defaultdict(set)
        self.asn_org = {}    
        self.asn_cc = {}    

        #Fingerprints
        self.fp_ips = defaultdict(set)
        self.fp_pkts = Counter()
        self.total_syn = 0
        self.mirai_port = {23:{'t':0,'m':0}, 2323:{'t':0,'m':0}}

        #Hourly
        self.hourly_pkts = Counter()
        self.hourly_bytes = Counter()
        self.hourly_tcp = Counter()
        self.hourly_udp = Counter()
        self.hourly_icmp = Counter()
        self.hourly_ips = defaultdict(set)
        self.hourly_tcp_ports = defaultdict(Counter)
        self.hourly_udp_ports = defaultdict(Counter)

        #Gap detection
        self.gaps = []
        self.prev_ts = None
        self.GAP_THRESH = 900

        #TTL
        self.ttl_dist = Counter()

        #TCP window
        self.win_dist = Counter()   

        #Unique port counts
        self.all_tcp_dst_ports = set()
        self.all_udp_dst_ports = set()
        self.all_tcp_src_ports = set()

        #Source ports
        self.tcp_src_pkts = Counter()
        self.udp_src_pkts = Counter()

        #Packet size distribution
        self.pkt_size_buckets = Counter()
        self.pkt_size_min = float('inf')
        self.pkt_size_max = 0
        self.pkt_size_sum = 0

        #Destination IP distribution
        self.dst_ip_pkts = Counter()
        self.dst_ip_bytes = Counter()
        self.dst_ip_ips = defaultdict(set)

        #aggregation
        self.slash24_pkts = Counter()
        self.slash24_ips = defaultdict(set)
        self.slash16_pkts = Counter()
        self.slash16_ips = defaultdict(set)

        #Backscatter (SYN|ACK)
        self.synack_pkts = 0
        self.synack_src_ips = set()
        self.synack_dst_ports = Counter()
        self.synack_src_top = Counter()

        #All IPs with protocol breakdown
        self.ip_full = defaultdict(lambda: {
            'tcp':0,'udp':0,'icmp':0,'packets':0,'bytes':0,'cc':'XX','asn':0
        })

        #MikroTik port-combo tracking
        self.mikrotik_ips = {8728: set(), 8291: set(), 1723: set()}

        #Per-country top ports
        self.cc_ports = defaultdict(Counter)

        #Continent and EU tracking
        self.continent_pkts = Counter()
        self.continent_ips  = defaultdict(set)
        self.continent_bytes= Counter()
        self.eu_pkts = 0
        self.eu_bytes = 0
        self.eu_ips = set()
        self.ip_continent = {} 

        #GeoIP / ASN setup med (MaxMind GeoLite2)
        self.cc_reader  = geoip2.database.Reader(MAXMIND_COUNTRY) if GEOIP_AVAILABLE else None
        self.asn_reader = geoip2.database.Reader(MAXMIND_ASN) if ASN_AVAILABLE   else None

    #PCAP location
    def locate_pcap(self):
        d = datetime.strptime(self.date_str, '%Y-%m-%d')
        fn = d.strftime('%Y%m%d.pcap')
        q = (d.month-1)//3+1

        for standalone in [
            os.path.join(BASE,f'data/raw/daily/{fn}'),
            os.path.join(BASE,f'data/raw/daily/2025Q{q}/{fn}'),
        ]:
            if os.path.exists(standalone):
                self.file_size_bytes = os.path.getsize(standalone)
                return standalone, False

        arch = os.path.join(BASE,f'data/raw/archived/Q{q}_{d.year}_daily.tar.gz')
        if not os.path.exists(arch):
            raise FileNotFoundError(f"PCAP not found for {self.date_str}")

        tmp = f'/tmp/ibr_{fn}'
        with tarfile.open(arch,'r:gz') as tar:
            mb = None
            for attempt in [fn, f'data/raw/daily/{fn}',
                            f'data/raw/daily/{d.year}Q{q}/{fn}']:
                try:    mb = tar.getmember(attempt); break
                except: pass
            if not mb: raise FileNotFoundError(f"{fn} not in archive")
            with tar.extractfile(mb) as src:
                data = src.read()
            with open(tmp,'wb') as dst: dst.write(data)
            self.file_size_bytes = len(data)
        return tmp, True

    #Main parse
    def parse(self, pcap_path):
        print(f"  Parsing {pcap_path}...")
        count = 0; t0 = time.time()
        with open(pcap_path,'rb') as f:
            for ts, buf in dpkt.pcap.Reader(f):
                count += 1
                if count % 300000 == 0:
                    e = time.time()-t0
                    print(f"  {count:,} pkts ({count/e:.0f} pkt/s)", end='\r')
                try:    self._packet(ts, buf)
                except: continue
        print(f"\n  Done: {count:,} packets in {time.time()-t0:.1f}s")

    def _packet(self, ts, buf):
        self.total_packets += 1
        sz = len(buf)
        self.total_bytes   += sz
        if self.first_ts is None: self.first_ts = ts
        self.last_ts = ts

        #gap detection
        if self.prev_ts is not None and (ts - self.prev_ts) > self.GAP_THRESH:
            self.gaps.append({'start_ts': self.prev_ts, 'end_ts': ts,
                              'duration_seconds': round(ts-self.prev_ts, 2)})
        self.prev_ts = ts

        
        self.pkt_size_sum += sz
        self.pkt_size_buckets[self._size_bucket(sz)] += 1
        if sz < self.pkt_size_min: self.pkt_size_min = sz
        if sz > self.pkt_size_max: self.pkt_size_max = sz

        try:    eth = dpkt.ethernet.Ethernet(buf)
        except: return
        if not isinstance(eth.data, dpkt.ip.IP): return
        ip = eth.data

        try:
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
        except: return

        #TTL
        self.ttl_dist[ip.ttl] += 1

        #source IP tracking
        self.src_ip_set.add(src_ip)
        self.ip_pkts[src_ip]  += 1
        self.ip_bytes[src_ip] += sz
        self.ip_dst_ips[src_ip].add(dst_ip)

        #Destination IP distribution
        self.dst_ip_pkts[dst_ip]  += 1
        self.dst_ip_bytes[dst_ip] += sz
        self.dst_ip_ips[dst_ip].add(src_ip)

        #/24 and /16 nettblock aggregation
        parts = src_ip.split('.')
        s24 = '.'.join(parts[:3]) + '.0/24'
        s16 = '.'.join(parts[:2]) + '.0.0/16'
        self.slash24_pkts[s24] += 1 
        self.slash24_ips[s24].add(src_ip)
        self.slash16_pkts[s16] += 1 
        self.slash16_ips[s16].add(src_ip)

        #GeoIP (MaxMind)
        cc = 'XX'
        if self.cc_reader:
            try:
                cc = self.cc_reader.country(src_ip).country.iso_code or 'XX'
            except: pass
        self.cc_pkts[cc]  += 1 
        self.cc_bytes[cc] += sz
        self.cc_ips[cc].add(src_ip)

        # ASN (MaxMind)
        asn = 0
        if self.asn_reader:
            try:
                r = self.asn_reader.asn(src_ip)
                asn = r.autonomous_system_number or 0
                if asn:
                    self.asn_pkts[asn]  += 1; self.asn_bytes[asn] += sz
                    self.asn_ips[asn].add(src_ip)
                    if asn not in self.asn_org:
                        self.asn_org[asn] = (r.autonomous_system_organization or '')[:40]
                        self.asn_cc[asn]  = cc
            except: pass

        #All IPs Protocol breakdown
        d = self.ip_full[src_ip]
        d['packets'] += 1; d['bytes'] += sz
        d['cc'] = cc; d['asn'] = asn

        #Continent and EU tracking
        if self.cc_reader:
            try:
                rec = self.cc_reader.country(src_ip)
                cont = rec.continent.code or 'XX'
                is_eu = bool(rec.country.is_in_european_union)
            except:
                cont = 'XX'
                is_eu = False
        else:
            cont  = 'XX'
            is_eu = False
        self.continent_pkts[cont] += 1
        self.continent_bytes[cont] += sz
        self.continent_ips[cont].add(src_ip)
        if is_eu:
            self.eu_pkts += 1
            self.eu_bytes += sz
            self.eu_ips.add(src_ip)

        # Hourly
        h = int(ts % 86400 // 3600)
        self.hourly_pkts[h] += 1
        self.hourly_bytes[h] += sz
        self.hourly_ips[h].add(src_ip)

        #Protocol dispatch
        proto = ip.data
        if isinstance(proto, dpkt.tcp.TCP):
            self._tcp(ip, proto, src_ip, dst_ip, ts, sz, h)
        elif isinstance(proto, dpkt.udp.UDP):
            self._udp(ip, proto, src_ip, ts, sz, h)
        elif isinstance(proto, dpkt.icmp.ICMP):
            self._icmp(ip, proto, src_ip, sz)
        else:
            self.proto_pkts['OTHER'] += 1
            self.proto_bytes['OTHER'] += sz

    def _tcp(self, ip, tcp, src_ip, dst_ip, ts, sz, h):
        self.proto_pkts['TCP'] += 1
        self.proto_bytes['TCP'] += sz
        dp = tcp.dport; sp = tcp.sport
        f  = tcp.flags

        #flags
        is_syn = bool(f & dpkt.tcp.TH_SYN)
        is_ack = bool(f & dpkt.tcp.TH_ACK)
        is_rst = bool(f & dpkt.tcp.TH_RST)
        is_fin = bool(f & dpkt.tcp.TH_FIN)
        is_psh = bool(f & dpkt.tcp.TH_PUSH)
        if   is_syn and is_ack:  self.flag_counts['SYN_ACK'] += 1
        elif is_syn: self.flag_counts['SYN'] += 1
        elif is_rst: self.flag_counts['RST'] += 1
        elif is_fin: self.flag_counts['FIN'] += 1
        elif is_psh: self.flag_counts['PSH'] += 1
        elif is_ack: self.flag_counts['ACK'] += 1
        else:        self.flag_counts['OTHER'] += 1

        #backscatter
        if is_syn and is_ack:
            self.synack_pkts += 1
            self.synack_src_ips.add(src_ip)
            self.synack_dst_ports[dp] += 1
            self.synack_src_top[src_ip] += 1

        #ports
        self.tcp_dst_pkts[dp] += 1
        self.tcp_dst_bytes[dp] += sz
        self.tcp_dst_ips[dp].add(src_ip)
        self.all_tcp_dst_ports.add(dp)
        self.all_tcp_src_ports.add(sp)

        #per-IP
        self.ip_proto[src_ip]["TCP"] += 1
        self.ip_full[src_ip]["tcp"] += 1
        self.ip_dst_ports[src_ip].add(dp)
        if dp in self.mikrotik_ips:
            self.mikrotik_ips[dp].add(src_ip)
        self.unique_src_ports_set.add(sp)

        
        self.tcp_src_pkts[sp] += 1

        
        self.hourly_tcp[h] += 1
        self.hourly_tcp_ports[h][dp]+= 1

        #YN-only
        if is_syn and not is_ack:
            self.total_syn += 1
            self.win_dist[tcp.win] += 1

            # Alle 13 fingerprints
            for sig in fingerprint(ip, tcp):
                self.fp_ips[sig].add(src_ip)
                self.fp_pkts[sig] += 1

            # Mirai per port
            if dp in self.mirai_port:
                self.mirai_port[dp]['t'] += 1
                try:
                    di = struct.unpack('>I', ip.dst)[0]
                    if tcp.seq == di: self.mirai_port[dp]['m'] += 1
                except: pass

    def _udp(self, ip, udp, src_ip, ts, sz, h):
        self.proto_pkts['UDP'] += 1
        self.proto_bytes['UDP'] += sz
        self.ip_full[src_ip]['udp'] += 1
        dp = udp.dport; sp = udp.sport
        self.udp_dst_pkts[dp] += 1
        self.udp_dst_bytes[dp] += sz
        self.udp_dst_ips[dp].add(src_ip)
        self.all_udp_dst_ports.add(dp)
        self.ip_proto[src_ip]['UDP'] += 1
        self.ip_dst_ports[src_ip].add(dp)
        if dp in self.mikrotik_ips:
            self.mikrotik_ips[dp].add(src_ip)
        self.unique_src_ports_set.add(sp)
        self.udp_src_pkts[sp] += 1
        self.hourly_udp[h] += 1
        self.hourly_udp_ports[h][dp] += 1

    def _icmp(self, ip, icmp, src_ip, sz):
        self.proto_pkts['ICMP'] += 1
        self.proto_bytes['ICMP'] += sz
        self.ip_full[src_ip]['icmp'] += 1
        try:
            tc = f"{icmp.type}_{icmp.code}"
            self.icmp_type_code_pkts[tc] += 1
            self.icmp_type_code_bytes[tc] += sz
            self.icmp_type_code_ips[tc].add(src_ip)
        except: pass
        self.ip_proto[src_ip]['ICMP'] += 1

    @staticmethod
    def _size_bucket(sz):
        if sz < 64: return '0-63'
        if sz < 128: return '64-127'
        if sz < 256: return '128-255'
        if sz < 512: return '256-511'
        if sz < 1024: return '512-1023'
        if sz < 1500: return '1024-1499'
        return '1500+'

    #Build output dict
    def build_output(self):
        total = self.total_packets or 1
        n_ips = len(self.src_ip_set)

        #churn
        prev_f = os.path.join(BASE,'data','parsed','ip_sets',
                              f"{(datetime.strptime(self.date_str,'%Y-%m-%d')-timedelta(days=1)).strftime('%Y-%m-%d')}.pkl.gz")
        prev_ips = set()
        if os.path.exists(prev_f):
            with gzip.open(prev_f,'rb') as f: prev_ips = pickle.load(f)
        new_ips = self.src_ip_set - prev_ips
        returning = self.src_ip_set & prev_ips
        churn_rate = len(new_ips) / n_ips if n_ips else 0

        #GHaps
        total_gap = sum(g['duration_seconds'] for g in self.gaps)
        dur = (self.last_ts - self.first_ts) if (self.first_ts and self.last_ts) else 86400
        uptime_pct = max(0, (dur - total_gap) / dur * 100) if dur > 0 else 100

        
        def scan_mode(dst_ip_count, dst_port_count):
            ip_cov = dst_ip_count / 256 * 100
            if ip_cov > 80 and dst_port_count > 100: return 'full_sweep'
            elif ip_cov > 80 and dst_port_count < 10:  return 'horizontal'
            elif ip_cov < 10 and dst_port_count > 100: return 'vertical'
            else: return 'targeted'

        top_src_ips = []
        for ip, pkts in self.ip_pkts.most_common(100):
            proto = self.ip_proto.get(ip, {})
            dp    = sorted(self.ip_dst_ports.get(ip, set()),
                          key=lambda p: self.tcp_dst_pkts.get(p,0)+self.udp_dst_pkts.get(p,0),
                          reverse=True)[:3]
            n_dst_ips = len(self.ip_dst_ips.get(ip, set()))
            n_dst_ports = len(self.ip_dst_ports.get(ip, set()))
            top_src_ips.append({
                'ip': ip, 'packets': pkts, 'bytes': self.ip_bytes.get(ip,0),
                'protocols': {'tcp': proto.get('TCP',0), 'udp': proto.get('UDP',0),
                              'icmp': proto.get('ICMP',0)},
                'top_3_dst_ports': dp,
                'unique_dst_ips': n_dst_ips,
                'unique_dst_ports': n_dst_ports,
                'dst_ip_coverage': round(n_dst_ips/256*100,1),
                'scan_mode': scan_mode(n_dst_ips, n_dst_ports),
            })

        out = {
           
            'date': self.date_str,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'first_packet_ts': self.first_ts,
            'last_packet_ts': self.last_ts,
            'duration_seconds': round(dur, 2),
            'file_size_bytes': self.file_size_bytes,
            'processing_time_sec': round(time.time()-self.t_start, 1),

           
            'protocols': {
                proto: {
                    'packets': self.proto_pkts[proto],
                    'bytes': self.proto_bytes[proto],
                    'percentage': round(self.proto_pkts[proto]/total*100, 3),
                }
                for proto in ['TCP','UDP','ICMP','OTHER']
            },

            
            'tcp_flags': dict(self.flag_counts),

            #Top 100 TCP/UDP ports
            'top_tcp_ports': [
                {'port': p, 'packets': c, 'bytes': self.tcp_dst_bytes[p],
                 'unique_src_ips': len(self.tcp_dst_ips[p])}
                for p,c in self.tcp_dst_pkts.most_common(100)
            ],
            'top_udp_ports': [
                {'port': p, 'packets': c, 'bytes': self.udp_dst_bytes[p],
                 'unique_src_ips': len(self.udp_dst_ips[p])}
                for p,c in self.udp_dst_pkts.most_common(100)
            ],

            #ICMP
            'icmp_types': [
                {'type_code': tc, 'packets': c,
                 'bytes': self.icmp_type_code_bytes[tc],
                 'unique_src_ips': len(self.icmp_type_code_ips[tc])}
                for tc,c in self.icmp_type_code_pkts.most_common(20)
            ],

            #Source IPs
            'unique_src_ips': n_ips,
            'unique_src_ports': len(self.unique_src_ports_set),
            'unique_dst_ips': len(self.dst_ip_pkts),
            'top_src_ips': top_src_ips,

            #Country / ASN (top 50)
            'top_countries': [
                {'country': cc, 'packets': c, 'bytes': self.cc_bytes[cc],
                 'unique_ips': len(self.cc_ips[cc])}
                for cc,c in self.cc_pkts.most_common(50)
            ],
            'top_countries_by_sources': [
                {'country': cc, 'unique_ips': len(ips), 'packets': self.cc_pkts[cc]}
                for cc,ips in sorted(self.cc_ips.items(), key=lambda x:-len(x[1]))[:50]
            ],
            'top_asns': [
                {'asn': asn, 'org': self.asn_org.get(asn,''), 'country': self.asn_cc.get(asn,''),
                 'packets': c, 'bytes': self.asn_bytes[asn],
                 'unique_ips': len(self.asn_ips[asn])}
                for asn,c in self.asn_pkts.most_common(50)
            ],
            'top_asns_by_sources': [
                {'asn': asn, 'org': self.asn_org.get(asn,''),
                 'unique_ips': len(ips), 'packets': self.asn_pkts[asn]}
                for asn,ips in sorted(self.asn_ips.items(), key=lambda x:-len(x[1]))[:50]
            ],

            #Churn
            'churn': {
                'new_ips_today': len(new_ips),
                'returning_ips_today':len(returning),
                'churn_rate': round(churn_rate, 4),
                'prev_day_available': os.path.exists(prev_f),
            },

            #Fingerprints
            'fingerprints': {
                'total_syn': self.total_syn,
                'signatures': {
                    sig: {
                        'unique_ips': len(self.fp_ips[sig]),
                        'packets': self.fp_pkts[sig],
                        'pct_syn': round(self.fp_pkts[sig]/self.total_syn*100, 4)
                                        if self.total_syn else 0,
                        'pct_syn_ips': round(len(self.fp_ips[sig])/self.total_syn*100, 4)
                                      if self.total_syn else 0,
                    }
                    for sig in ALL_SIGS
                },
            },
            'mirai_per_port': {
                str(p): {
                    'total': d['t'], 'mirai': d['m'],
                    'mirai_pct': round(d['m']/d['t']*100,2) if d['t'] else 0,
                }
                for p,d in self.mirai_port.items()
            },

            #Hourly
            'hourly': [
                {
                    'hour': h, 'packets': self.hourly_pkts[h],
                    'bytes': self.hourly_bytes[h],
                    'tcp_packets': self.hourly_tcp[h],
                    'udp_packets': self.hourly_udp[h],
                    'icmp_packets': self.hourly_icmp[h],
                    'unique_src_ips': len(self.hourly_ips[h]),
                    'top_tcp_ports': [
                        {'port': p, 'packets': c}
                        for p,c in self.hourly_tcp_ports[h].most_common(10)
                    ],
                    'top_udp_ports': [
                        {'port': p, 'packets': c}
                        for p,c in self.hourly_udp_ports[h].most_common(10)
                    ],
                }
                for h in range(24)
            ],

            #Gaps
            'gaps': self.gaps,
            'total_gap_seconds': round(total_gap, 2),
            'uptime_pct': round(uptime_pct, 2),

           
            'ttl_distribution': [
                {'ttl': t, 'packets': c}
                for t,c in self.ttl_dist.most_common(20)
            ],

            #TCP window (SYN only)
            'tcp_window_distribution': [
                {'window': w, 'count': c,
                 'pct_syn': round(c/self.total_syn*100,3) if self.total_syn else 0}
                for w,c in self.win_dist.most_common(20)
            ],


            'unique_tcp_dst_ports': len(self.all_tcp_dst_ports),
            'unique_udp_dst_ports': len(self.all_udp_dst_ports),
            'unique_tcp_src_ports': len(self.all_tcp_src_ports),

            'top_tcp_src_ports': [
                {'port': p, 'packets': c}
                for p,c in self.tcp_src_pkts.most_common(50)
            ],
            'top_udp_src_ports': [
                {'port': p, 'packets': c}
                for p,c in self.udp_src_pkts.most_common(50)
            ],


            'packet_size_stats': {
                'min': self.pkt_size_min if self.total_packets else 0,
                'max': self.pkt_size_max,
                'avg': round(self.pkt_size_sum/self.total_packets,1) if self.total_packets else 0,
                'distribution': dict(self.pkt_size_buckets),
            },

            'dst_ip_distribution': [
                {'ip': ip, 'packets': c, 'bytes': self.dst_ip_bytes[ip],
                 'unique_src_ips': len(self.dst_ip_ips[ip])}
                for ip,c in self.dst_ip_pkts.most_common(256)
            ],

            'top_slash24': [
                {'prefix': p, 'packets': c, 'unique_ips': len(self.slash24_ips[p])}
                for p,c in self.slash24_pkts.most_common(100)
            ],

            
            'top_slash16': [
                {'prefix': p, 'packets': c, 'unique_ips': len(self.slash16_ips[p]),
                 'unique_slash24s': len(set(
                     s24 for s24 in self.slash24_ips
                     if s24.startswith(p.split('/')[0][:p.rfind('.',0,p.rfind('.'))+1])
                 ))}

                for p,c in self.slash16_pkts.most_common(50)
            ],


            'backscatter': {
                'total_synack_packets': self.synack_pkts,
                'unique_synack_sources': len(self.synack_src_ips),
                'top_20_synack_dst_ports': [
                    {'port': p, 'packets': c}
                    for p,c in self.synack_dst_ports.most_common(20)
                ],
                'top_20_synack_src_ips': [
                    {'ip': ip, 'packets': c}

                    for ip,c in self.synack_src_top.most_common(20)
                ],
            },

            #MikroTik port-combo
            'mikrotik_ports': {
                'ips_8728': len(self.mikrotik_ips[8728]),
                'ips_8291': len(self.mikrotik_ips[8291]),
                'ips_1723': len(self.mikrotik_ips[1723]),
                'overlap_8728_8291': len(self.mikrotik_ips[8728] & self.mikrotik_ips[8291]),
                'overlap_8728_1723': len(self.mikrotik_ips[8728] & self.mikrotik_ips[1723]),
                'overlap_all_three': len(self.mikrotik_ips[8728] & self.mikrotik_ips[8291] & self.mikrotik_ips[1723]),
            },

            #Per-country top TCP port
            'country_top_ports': {
                cc: [{'port': p, 'packets': c}
                     for p,c in self.cc_ports[cc].most_common(10)]
                for cc, _ in self.cc_pkts.most_common(20)
                if cc in self.cc_ports
            },

            #Continent and EU breakdown
            'continents': [
                {
                    'continent': cont,
                    'packets': cnt,
                    'bytes': self.continent_bytes[cont],
                    'unique_ips':len(self.continent_ips[cont]),
                    'pct': round(cnt/total*100, 3) if total else 0,
                }
                for cont, cnt in self.continent_pkts.most_common()
            ],
            'eu_traffic': {
                'packets': self.eu_pkts,
                'bytes': self.eu_bytes,
                'unique_ips': len(self.eu_ips),
                'pct': round(self.eu_pkts/total*100, 3) if total else 0,
            },
        }
        return out


    def save(self, out):
        daily_dir = os.path.join(BASE,'data','parsed','daily')
        os.makedirs(daily_dir, exist_ok=True)
        out_f = os.path.join(daily_dir, f'{self.date_str}.json')
        with open(out_f,'w') as f: json.dump(out, f, indent=2)
        print(f"  Saved: {out_f}")
        ip_dir = os.path.join(BASE,'data','parsed','ip_activity')
        os.makedirs(ip_dir, exist_ok=True)
        ip_f = os.path.join(ip_dir, f'{self.date_str}.csv')

        with open(ip_f,'w',newline='') as f:
            w = csv.DictWriter(f, fieldnames=[
                'date','ip','packets','bytes','tcp','udp','icmp','cc','asn'])
            w.writeheader()

            for ip, d in sorted(self.ip_full.items(),
                                 key=lambda x: -x[1]['packets']):
                w.writerow({
                    'date': self.date_str, 'ip': ip,
                    'packets': d['packets'], 'bytes': d['bytes'],
                    'tcp': d['tcp'], 'udp': d['udp'], 'icmp': d['icmp'],
                    'cc': d['cc'], 'asn': d['asn'],
                })
        print(f"  Saved: {ip_f} ({len(self.ip_full):,} IPs)")

        # Save IP set for next-day churn calculation
        ip_set_dir = os.path.join(BASE,'data','parsed','ip_sets')
        os.makedirs(ip_set_dir, exist_ok=True)
        ip_set_f = os.path.join(ip_set_dir, f'{self.date_str}.pkl.gz')
        with gzip.open(ip_set_f,'wb') as f: pickle.dump(self.src_ip_set, f)
        print(f"  Saved IP set: {ip_set_f} ({len(self.src_ip_set):,} IPs)")

    def print_summary(self, out):
        print(f"\n{'='*60}")
        print(f"  {self.date_str}  {out['total_packets']:,} pkts  "
              f"{out['total_bytes']/1e6:.1f} MB  {out['unique_src_ips']:,} IPs")
        print(f"{'='*60}")

        for p in ['TCP','UDP','ICMP']:
            pr = out['protocols'].get(p,{})
            print(f"  {p:<6} {pr.get('packets',0):>10,}  {pr.get('percentage',0):.1f}%  "
                  f"{pr.get('bytes',0)/1e6:.1f} MB")
        print(f"\n  Churn: {out['churn']['churn_rate']*100:.1f}%  "
              f"({out['churn']['new_ips_today']:,} new)")
        print(f"  Gaps:  {len(out['gaps'])} gaps, {out['total_gap_seconds']:.0f}s "
              f"({100-out['uptime_pct']:.2f}% downtime)")
        fp = out['fingerprints']
        sigs = fp['signatures']
        active = [(s, sigs[s]) for s in ALL_SIGS if sigs[s]['unique_ips']>0]

        if active:
            print(f"\n  Fingerprints ({fp['total_syn']:,} SYN):")
            for s,v in sorted(active, key=lambda x:-x[1]['pct_syn_ips'])[:6]:
                print(f"    {s:<14} {v['unique_ips']:>8,} IPs  {v['pct_syn_ips']:.3f}% (IPs)  {v['pct_syn']:.2f}% (pkts)")
        bs = out['backscatter']

        if bs['total_synack_packets']:
            print(f"\n  Backscatter: {bs['total_synack_packets']:,} SYN|ACK "
                  f"from {bs['unique_synack_sources']:,} sources")


def main():
    parser = argparse.ArgumentParser(description='SANREN IBR PCAP parser v2')
    parser.add_argument('date')
    parser.add_argument('--hourly',   action='store_true')
    parser.add_argument('--detailed', action='store_true')
    args = parser.parse_args()

    try: datetime.strptime(args.date, '%Y-%m-%d')
    except ValueError: print("Date must be YYYY-MM-DD"); sys.exit(1)

    p = IBRParser(args.date,
                  hourly=args.hourly or args.detailed,
                  detailed=args.detailed)

    pcap_path, cleanup = p.locate_pcap()
    p.parse(pcap_path)
    if cleanup and os.path.exists(pcap_path): os.remove(pcap_path)

    out = p.build_output()
    p.save(out)
    p.print_summary(out)


if __name__ == '__main__':
    main()