#!/usr/bin/env python3

import json, os, sys, subprocess, calendar, shutil
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from metrics_adapter import adapt_metrics

BASE      = os.path.join(os.path.expanduser('~'), 'ibr-analyst')
DAILY_DIR = os.path.join(BASE, 'data', 'parsed', 'daily')
ANOM_FILE = os.path.join(BASE, 'data', 'parsed', 'anomalies_daily.json')
TMPL_DIR  = os.path.join(BASE, 'templates')

#Port + ASN helpers
PORT_NAMES = {
    22:'SSH', 23:'Telnet', 53:'DNS', 80:'HTTP', 123:'NTP', 137:'NetBIOS',
    161:'SNMP', 389:'LDAP', 443:'HTTPS', 445:'SMB', 500:'IKE',
    1194:'OpenVPN', 1433:'MSSQL', 1434:'MSSQL-UDP', 1900:'SSDP',
    2222:'SSH-alt', 2375:'Docker', 3306:'MySQL', 3389:'RDP',
    3478:'STUN', 3702:'WS-Discov.', 5060:'SIP', 5353:'mDNS',
    5432:'PostgreSQL', 5555:'ADB', 5683:'CoAP', 6379:'Redis',
    8080:'HTTP-alt', 8291:'Winbox', 8443:'HTTPS-alt', 8728:'MikroTik API',
    9200:'Elasticsearch', 27017:'MongoDB', 34567:'NetSurv.',
}
def pname(p):
    return PORT_NAMES.get(int(p), f'Port~{p}')

def load_asn_names():
    path = os.path.join(BASE, 'lib', 'asn_names.txt')
    names = {}
    if not os.path.exists(path): return names
    with open(path, encoding='latin-1') as f:
        for line in f:
            parts = line.strip().split(' ', 1)
            if len(parts) != 2: continue
            try:
                asn= int(parts[0])
                rest = parts[1]
                if len(rest) > 5 and rest[-4] == ',': rest = rest[:-5].strip()
                name = rest.split(' - ', 1)[1].strip() if ' - ' in rest else rest.split(',')[0].strip()
                names[asn] = name[:24]
            except: pass
    return names

def load_anomalies_for(date_prefix):
    if not os.path.exists(ANOM_FILE): return [], set()
    with open(ANOM_FILE) as f:
        all_a = json.load(f).get('anomalies', [])
    details = [a for a in all_a if a['date'].startswith(date_prefix)]
    dates = {a['date'] for a in details}
    return details, dates

#Escape TeX special chars
def esc(s):
    s = str(s)
    for ch, rep in [
        ('\\','\\textbackslash{}'),('&','\\&'),('%','\\%'),
        ('$','\\$'),('#','\\#'),('^','\\^{}'),('_','\\_'),
        ('{','\\{'),('}','\\}'),('~','\\textasciitilde{}'),
    ]:
        s = s.replace(ch, rep)
    return s

def fmtn(n):
    n = int(n)
    if n >= 1_000_000: return f'{n/1_000_000:.2f}M'
    if n >= 1_000: return f'{n/1_000:.1f}K'
    return str(n)

def fmtp(p): return f'{float(p):.1f}\\%'

def altrow(i): return r'\rowcolor{lightbg}' if i % 2 == 1 else ''

def delta_fmt(today, avg):
    if avg == 0: return '{\\color{mutedgray}---}'
    pct = (today - avg) / avg * 100
    if abs(pct) < 0.1: return '{\\color{mutedgray}---}'
    col = 'okgreen' if pct > 0 else 'alertred'
    arrow = '$\\uparrow$' if pct > 0 else '$\\downarrow$'
    return f'{{\\color{{{col}}}{arrow} {abs(pct):.1f}\\%}}'


def previous_proto_average(records, proto):
    """Calculate average protocol percentage from previous records."""
    if not records:
        return 0
    values = []
    for _, m in records:
        proto_data = m.get('protocols', {}).get(proto, {})
        if isinstance(proto_data, dict):
            pct = proto_data.get('percentage', 0)
        else:
            total = max(m.get('total_packets', 1), 1)
            pct = proto_data / total * 100
        values.append(pct)
    return sum(values) / len(values)

def protobar(tcp, udp, icmp, W=8.0, H=0.28):
    bars, x = [], 0.0
    for pct, col in [(tcp,'tcpblue'),(udp,'udporange'),(icmp,'icmpred'),
                     (max(0, 100-tcp-udp-icmp),'mutedgray')]:
        w = pct / 100 * W
        if w > 0.02:
            bars.append(f'  \\fill[{col}] ({x:.3f},0) rectangle ({x+w:.3f},{H});')
            x += w
    return '\\begin{tikzpicture}[baseline=0]\n' + '\n'.join(bars) + '\n\\end{tikzpicture}'

def barchart(values, labels, W=14.0, H=2.0, anomaly_dates=None):
    if not values: return ''
    mx  = max(values) or 1
    n = len(values)
    bw = W / n * 0.72
    gap = W / n
    lines = ['\\begin{tikzpicture}[baseline=-0.5ex]']
    for i, (val, lbl) in enumerate(zip(values, labels)):
        h = max(val / mx * H, 0.02)
        x = i * gap + gap * 0.14
        cx = x + bw / 2
        is_anom = anomaly_dates and lbl in anomaly_dates
        col = 'alertred!70' if is_anom else ('accentblue' if i == n-1 else 'accentblue!45')
        lines.append(f'  \\fill[{col}] ({x:.3f},0) rectangle ({x+bw:.3f},{h:.3f});')
        if i % max(1, n//14) == 0 or i == n-1:
            short = lbl[8:] if len(lbl) == 10 else lbl 
            lines.append(f'  \\node[font=\\tiny,color=mutedgray,anchor=north,inner sep=1pt] at ({cx:.3f},-0.01) {{{esc(short)}}};')
    lines.append('\\end{tikzpicture}')
    return '\n'.join(lines)

#DATA FILE WRITERS
def write_daily_data(metrics_file, asn_names, out_path):
    with open(metrics_file) as f:
        m = adapt_metrics(json.load(f))

    date = Path(metrics_file).stem
    total = m.get('total_packets', 0)
    unique = m.get('unique_src_ips', 0)
    protos = m.get('protocols', {})
    tcp_n = protos.get('TCP', 0)
    udp_n = protos.get('UDP', 0)
    icmp_n = protos.get('ICMP', 0)
    tcp_p = tcp_n / total * 100 if total else 0
    udp_p = udp_n / total * 100 if total else 0
    icmp_p = icmp_n / total * 100 if total else 0

    # 7-day recent data
    recent = []
    for f in sorted(Path(DAILY_DIR).glob('????-??-??.json')):
        if f.stem <= date:
            try:
                with open(f) as fh: recent.append((f.stem, adapt_metrics(json.load(fh))))
            except: pass
    recent = recent[-8:]
    prev7 = recent[:-1]

    a7p = sum(r[1].get('total_packets',0) for r in prev7) / len(prev7) if prev7 else 0
    a7u = sum(r[1].get('unique_src_ips',0) for r in prev7) / len(prev7) if prev7 else 0
    a7t = sum(r[1].get('protocols',{}).get('TCP',0)/max(r[1].get('total_packets',1),1)*100 for r in prev7) / len(prev7) if prev7 else 0
    a7ud = sum(r[1].get('protocols',{}).get('UDP',0)/max(r[1].get('total_packets',1),1)*100 for r in prev7) / len(prev7) if prev7 else 0
    a7ic = sum(r[1].get('protocols',{}).get('ICMP',0)/max(r[1].get('total_packets',1),1)*100 for r in prev7) / len(prev7) if prev7 else 0

    # Bar chart
    bar_vals = [r[1].get('total_packets',0) for r in recent]
    bar_labels = [r[0][5:] for r in recent]

    # Ports
    ports = m.get('top_ports', {})
    top_tcp = sorted(ports.items(), key=lambda x: -x[1])[:10]
    top_udp = m.get('top_udp_ports', [])[:10]

    # Geo + ASN
    top_geo  = m.get('top_countries_by_sources', [])[:10]
    geo_pkts = {e['country']: e['packets'] for e in m.get('top_countries', [])}
    top_asn  = m.get("top_asns_by_sources", [])[:5]
    tot = total or 1

    # Anomaly
    anom_details, _ = load_anomalies_for(date)
    is_anom = bool(anom_details)

    lines = []
    snippet_dir = os.path.dirname(out_path)
    def cmd(name, val):
        val_s = str(val)
        if '\n' in val_s:
            snip = os.path.join(snippet_dir, f'snip_{name}.tex')
            with open(snip, 'w') as sf:
                sf.write(f'\\newcommand{{\\{name}}}{{%\n{val_s}}}\n')
            lines.append(f'\\input{{{snip}}}')
        else:
            lines.append(f'\\newcommand{{\\{name}}}{{{val_s}}}')

    cmd('reportdate', esc(date))
    cmd('generatedtime', datetime.now().strftime('%Y-%m-%d %H:%M'))
    cmd('statuscolor', 'alertred' if is_anom else 'okgreen')
    cmd('statusbg', 'alertbg'  if is_anom else 'okbg')
    cmd('statustext', 'Status: ANOMALY DETECTED' if is_anom else 'Status: NORMAL OPERATIONS')
    cmd('statusnote',  esc('Anomaly detected. See detail below.' if is_anom else 'No anomalies detected. All metrics within expected ranges.'))

    cmd('metricpackets', fmtn(total))
    cmd('metricips', fmtn(unique))
    cmd('metrictcp', fmtp(tcp_p))
    cmd('metricudp', fmtp(udp_p))
    cmd('metricicmp', fmtp(icmp_p))
    cmd('avgpackets', fmtn(a7p))
    cmd('avgips', fmtn(a7u))
    cmd('avgtcp', fmtp(a7t))
    cmd('avgudp', fmtp(a7ud))
    cmd('avgicmp', fmtp(a7ic))
    cmd('deltapackets', delta_fmt(total, a7p))
    cmd('deltaips', delta_fmt(unique, a7u))
    cmd('deltatcp', delta_fmt(tcp_p, a7t))
    cmd('deltaudp', delta_fmt(udp_p, a7ud))
    cmd('deltaicmp', delta_fmt(icmp_p, a7ic))

    cmd('protobar', protobar(tcp_p, udp_p, icmp_p))
    cmd('barchart', barchart(bar_vals, bar_labels))

    # TCP rows
    tcp_rows = ''
    for i, (port, cnt) in enumerate(top_tcp):
        tcp_rows += f'{altrow(i)}{i+1} & {port} & {esc(pname(port))} & {fmtn(cnt)} & {fmtp(cnt/tot*100)} \\\\\n'
    cmd('tcprows', tcp_rows)

    # UDP rows
    udp_rows = ''
    for i, e in enumerate(top_udp):
        port, cnt = e['port'], e['packets']
        udp_rows += f'{altrow(i)}{i+1} & {port} & {esc(pname(port))} & {fmtn(cnt)} & {fmtp(cnt/tot*100)} \\\\\n'
    cmd('udprows', udp_rows)

    # Geo rows
    geo_rows = ''
    for i, e in enumerate(top_geo):
        cc = e['country']
        uips = e.get('unique_ips', 0)
        pkts = geo_pkts.get(cc, 0)
        geo_rows += f'{altrow(i)}{i+1} & {esc(cc)} & {fmtn(pkts)} & {fmtp(pkts/tot*100)} & {fmtn(uips)} \\\\\n'
    cmd('georows', geo_rows)

    asn_rows = ''
    for i, e in enumerate(top_asn):
        asn = e['asn']
        uips = e.get('unique_ips', 0)
        name = asn_names.get(asn, f'AS{asn}')
        name = name.split(',')[0].split(' - ')[-1].strip()
        asn_rows += f'{altrow(i)}{i+1} & AS{asn} & {esc(name[:22])} & {fmtn(uips)} \\\\\n'
    cmd('asnrows', asn_rows)

    # Anomaly detail
    if anom_details:
        rows = ''
        for i, a in enumerate(anom_details):
            params = esc(', '.join(a.get('parameters_triggered', [])))
            for al in a.get('alerts', []):
                param = al.get('parameter', '---')
                # Handle different alert formats
                if param == 'source_count':
                    val = al.get('value', 0)
                    base = al.get('median', 0)
                    dev = al.get('deviation_mad_units', 0)
                    dev_str = f'{dev:.1f}x MAD'
                elif param == 'port_concentration':
                    val = al.get('today_share_pct', 0)
                    base = al.get('baseline_mean_pct', 0)
                    dev = al.get('deviation_pp', 0)
                    dev_str = f'{dev:+.1f} pp'
                elif param == 'churn_rate':
                    val = al.get('value', 0) * 100
                    base = al.get('quarterly_mean', 0) * 100
                    dev = (val - base)
                    dev_str = f'{dev:+.1f} pp'
                else:
                    val = al.get('value', 0)
                    base = al.get('baseline', 0)
                    dev = al.get('deviation_pct', al.get('deviation_mad_units', 0))
                    dev_str = f'{dev:+.1f}%'
                val_str = f'{val:.1f}\\%' if param in ('port_concentration','churn_rate') else fmtn(int(val))
                base_str = f'{base:.1f}\\%' if param in ('port_concentration','churn_rate') else fmtn(int(base))
                rows += f'{altrow(i)}{esc(param)} & {val_str} & {base_str} & {dev_str} \\\\\n'
        anom_block = (
            r'\vspace{3mm}' + '\n'
            r'{\footnotesize\bfseries\color{alertred} ANOMALY DETAIL}\\[1mm]' + '\n'
            r'\begin{tabular}{L{38mm} R{20mm} R{20mm} R{20mm}}' + '\n'
            r'\toprule' + '\n'
            r'\rowcolor{headerdk}' + '\n'
            r'{\color{white}\bfseries\small Parameter} & '
            r'{\color{white}\bfseries\small Today} & '
            r'{\color{white}\bfseries\small Baseline} & '
            r'{\color{white}\bfseries\small Deviation} \\' + '\n'
            r'\midrule' + '\n' + rows +
            r'\bottomrule' + '\n'
            r'\end{tabular}'
        )
    else:
        anom_block = ''
    cmd('anomalydetail', anom_block)

    with open(out_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def write_weekly_data(end_date, asn_names, out_path):
    end = datetime.strptime(end_date, '%Y-%m-%d')
    days = [(end - timedelta(days=6-i)).strftime('%Y-%m-%d') for i in range(7)]
    start = days[0]

    records, prev_records = [], []
    for d in days:
        p = os.path.join(DAILY_DIR, f'{d}.json')
        if os.path.exists(p):
            try:
                with open(p) as f: records.append((d, adapt_metrics(json.load(f))))
            except: pass
    prev_end = end - timedelta(days=7)
    prev_days = [(prev_end - timedelta(days=6-i)).strftime('%Y-%m-%d') for i in range(7)]
    for d in prev_days:
        p = os.path.join(DAILY_DIR, f'{d}.json')
        if os.path.exists(p):
            try:
                with open(p) as f: prev_records.append((d, adapt_metrics(json.load(f))))
            except: pass

    anom_details, anom_dates = load_anomalies_for('')
    anom_details = [a for a in anom_details if start <= a['date'] <= end_date]
    anom_dates = {a['date'] for a in anom_details}

    total_pkts = sum(m.get('total_packets',0) for _,m in records)
    total_ips = sum(m.get('unique_src_ips',0) for _,m in records)
    daily_avg = total_pkts // len(records) if records else 0
    prev_total = sum(m.get('total_packets',0) for _,m in prev_records)
    prev_avg = prev_total // len(prev_records) if prev_records else 0
    prev_ips = sum(m.get('unique_src_ips',0) for _,m in prev_records)
    tcp_avg = sum(m.get('protocols',{}).get('TCP',0)/max(m.get('total_packets',1),1)*100 for _,m in records) / len(records) if records else 0
    udp_avg = sum(m.get('protocols',{}).get('UDP',0)/max(m.get('total_packets',1),1)*100 for _,m in records) / len(records) if records else 0
    icmp_avg = sum(m.get('protocols',{}).get('ICMP',0)/max(m.get('total_packets',1),1)*100 for _,m in records) / len(records) if records else 0
    tot = total_pkts or 1

    tcp_t, udp_t = defaultdict(int), defaultdict(int)
    prev_tcp, prev_udp = defaultdict(int), defaultdict(int)
    for _,m in records:
        for p,c in m.get('top_ports',{}).items(): tcp_t[int(p)] += c
        for e in m.get('top_udp_ports',[]): udp_t[e['port']] += e['packets']
    for _,m in prev_records:
        for p,c in m.get('top_ports',{}).items(): prev_tcp[int(p)] += c
        for e in m.get('top_udp_ports',[]): prev_udp[e['port']] += e['packets']
    top10_tcp = sorted(tcp_t.items(), key=lambda x:-x[1])[:10]
    top10_udp = sorted(udp_t.items(), key=lambda x:-x[1])[:10]
    prev_tcp10 = {p for p,_ in sorted(prev_tcp.items(), key=lambda x:-x[1])[:10]}
    prev_udp10 = {p for p,_ in sorted(prev_udp.items(), key=lambda x:-x[1])[:10]}
    new_tcp = {p for p,_ in top10_tcp} - prev_tcp10
    new_udp = {p for p,_ in top10_udp} - prev_udp10

    geo_pkts, geo_ips = defaultdict(int), defaultdict(int)
    asn_t = defaultdict(int)
    for _,m in records:
        for e in m.get('top_countries',[]): geo_pkts[e['country']] += e['packets']
        for e in m.get('top_countries_by_sources',[]): geo_ips[e['country']] += e.get('unique_ips',0)
        for e in m.get('top_asns_by_sources',[]): asn_t[e['asn']] += e.get('unique_ips',0)
    top10_geo = sorted(geo_pkts.items(), key=lambda x:-x[1])[:10]
    top5_asn = sorted(asn_t.items(), key=lambda x:-x[1])[:5]

    bar_vals = [m.get('total_packets',0) for _,m in records]
    bar_labels = [d[5:] for d,_ in records]

    n_anom = len(anom_dates)
    lines = []
    snippet_dir = os.path.dirname(out_path)
    def cmd(name, val):
        val_s = str(val)
        if '\n' in val_s:

            snip = os.path.join(snippet_dir, f'snip_{name}.tex')
            with open(snip, 'w') as sf:
                sf.write(f'\\newcommand{{\\{name}}}{{%\n{val_s}}}\n')
            lines.append(f'\\input{{{snip}}}')
        else:
            lines.append(f'\\newcommand{{\\{name}}}{{{val_s}}}')

    cmd('weeklabel', esc(f'{start} to {end_date}'))
    cmd('generatedtime', datetime.now().strftime('%Y-%m-%d %H:%M'))
    cmd('statuscolor', 'alertred' if n_anom else 'okgreen')
    cmd('statusbg', 'alertbg'  if n_anom else 'okbg')
    cmd('statustext', f'{n_anom} ANOMALY DAY(S) THIS WEEK' if n_anom else 'NORMAL WEEK')
    cmd('statusnote',  esc(f'Anomaly days: {", ".join(sorted(anom_dates))}' if n_anom else 'All metrics within expected ranges.'))
    cmd('tcppct', fmtp(tcp_avg))
    cmd('udppct', fmtp(udp_avg))
    cmd('icmppct', fmtp(icmp_avg))
    cmd('protobar', protobar(tcp_avg, udp_avg, icmp_avg))
    cmd('barchart', barchart(bar_vals, bar_labels))

    # Metrics rows
    prev_tcp_avg = previous_proto_average(prev_records, 'TCP')
    prev_udp_avg = previous_proto_average(prev_records, 'UDP')

    mr = f'Total Packets & {fmtn(total_pkts)} & {fmtn(prev_total)} & {delta_fmt(total_pkts,prev_total)} \\\\\n'
    mr += f'\\rowcolor{{lightbg}}Daily Average & {fmtn(daily_avg)} & {fmtn(prev_avg)} & {delta_fmt(daily_avg,prev_avg)} \\\\\n'
    mr += f'Unique Source IPs & {fmtn(total_ips)} & {fmtn(prev_ips)} & {delta_fmt(total_ips,prev_ips)} \\\\\n'
    mr += f'\\rowcolor{{lightbg}}TCP & {fmtp(tcp_avg)} & {fmtp(prev_tcp_avg)} & {delta_fmt(tcp_avg, prev_tcp_avg)} \\\\\n'
    mr += f'UDP & {fmtp(udp_avg)} & {fmtp(prev_udp_avg)} & {delta_fmt(udp_avg, prev_udp_avg)} \\\\\n'
    cmd('metricsrows', mr)


    dr = ''
    for i, d in enumerate(days):
        rec = next((m for dd,m in records if dd==d), None)
        is_a = d in anom_dates
        bg   = r'\rowcolor{alertbg}' if is_a else (r'\rowcolor{lightbg}' if i%2==1 else '')
        pkts = fmtn(rec.get('total_packets',0)) if rec else r'{\color{mutedgray}---}'
        uips = fmtn(rec.get('unique_src_ips',0)) if rec else r'{\color{mutedgray}---}'
        flag = r'{\color{alertred}\bfseries ANOMALY}' if is_a else (r'{\color{mutedgray}---}' if rec else r'{\color{mutedgray}MISSING}')
        dr += f'{bg}{esc(d)} & {pkts} & {uips} & {flag} \\\\\n'
    cmd('dayrows', dr)

    # TCP + UDP rows
    tcp_rows = ''
    for i,(port,cnt) in enumerate(top10_tcp):
        star = r'{\color{okgreen}$\star$}' if port in new_tcp else ''
        tcp_rows += f'{altrow(i)}{i+1} & {port} & {esc(pname(port))} & {fmtn(cnt)} & {fmtp(cnt/tot*100)} & {star} \\\\\n'
    cmd('tcprows', tcp_rows)

    udp_rows = ''
    for i,(port,cnt) in enumerate(top10_udp):
        star = r'{\color{okgreen}$\star$}' if port in new_udp else ''
        udp_rows += f'{altrow(i)}{i+1} & {port} & {esc(pname(port))} & {fmtn(cnt)} & {fmtp(cnt/tot*100)} & {star} \\\\\n'
    cmd('udprows', udp_rows)

    geo_rows = ''
    for i,(cc,cnt) in enumerate(top10_geo):
        geo_rows += f'{altrow(i)}{i+1} & {esc(cc)} & {fmtn(cnt)} & {fmtp(cnt/tot*100)} & {fmtn(geo_ips.get(cc,0))} \\\\\n'
    cmd('georows', geo_rows)

    asn_rows = ''
    for i,(asn,cnt) in enumerate(top5_asn):
        raw = asn_names.get(asn, f'AS{asn}')
        raw = raw.split(',')[0].split(' - ')[-1].strip()
        asn_rows += f'{altrow(i)}{i+1} & AS{asn} & {esc(raw[:22])} & {fmtn(cnt)} \\\\\n'
    cmd('asnrows', asn_rows)


    if anom_details:
        arows = ''
        for i,a in enumerate(sorted(anom_details, key=lambda x:x['date'])):
            params = esc(', '.join(a.get('parameters_triggered',[])))
            arows += f'{altrow(i)}{esc(a["date"])} & {fmtn(a.get("total_packets",0))} & {params} \\\\\n'
        anom_block = (
            r'\vspace{3mm}' + '\n'
            r'{\footnotesize\bfseries\color{alertred} ANOMALY DAYS THIS WEEK}\\[1mm]' + '\n'
            r'\begin{tabular}{L{26mm} R{20mm} L{100mm}}' + '\n'
            r'\toprule' + '\n'
            r'\rowcolor{headerdk}{\color{white}\bfseries\small Date} & '
            r'{\color{white}\bfseries\small Packets} & '
            r'{\color{white}\bfseries\small Parameters} \\' + '\n'
            r'\midrule' + '\n' + arows +
            r'\bottomrule' + '\n' + r'\end{tabular}'
        )
    else:
        anom_block = ''
    cmd('anomalydetail', anom_block)

    with open(out_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def write_monthly_data(year_month, asn_names, out_path):
    year, month = int(year_month[:4]), int(year_month[5:7])
    _, ndays = calendar.monthrange(year, month)
    records = []
    for d in range(1, ndays+1):
        ds = f'{year_month}-{d:02d}'
        p  = os.path.join(DAILY_DIR, f'{ds}.json')
        if os.path.exists(p):
            try:
                with open(p) as f: records.append((ds, adapt_metrics(json.load(f))))
            except: pass

    # Previous month
    pm = month - 1
    py = year
    if pm == 0: pm, py = 12, year-1
    prev_ym = f'{py}-{pm:02d}'
    _, pndays = calendar.monthrange(py, pm)
    prev_records = []
    for d in range(1, pndays+1):
        ds = f'{prev_ym}-{d:02d}'
        p  = os.path.join(DAILY_DIR, f'{ds}.json')
        if os.path.exists(p):
            try:
                with open(p) as f: prev_records.append((ds, adapt_metrics(json.load(f))))
            except: pass

    anom_details, anom_dates = load_anomalies_for(year_month + '-')
    prev_month = prev_ym
    prev_anom_details, _ = load_anomalies_for(prev_month + '-')
    prev_n_anom_count = len(prev_anom_details)

    # Gap data
    try:
        from gap_detector import load_gap_result
        gap = load_gap_result(year_month)
    except: gap = None
    gaps_found = gap.get('gaps_found',0) if gap else 0
    downtime_h = round(gap.get('total_gap_seconds',0)/3600,1) if gap else 0
    uptime_pct = gap.get('uptime_pct',100.0) if gap else 100.0

    total_pkts = sum(m.get('total_packets',0) for _,m in records)
    total_ips = sum(m.get('unique_src_ips',0) for _,m in records)
    daily_avg = total_pkts // len(records) if records else 0
    prev_total = sum(m.get('total_packets',0) for _,m in prev_records)
    prev_avg = prev_total // len(prev_records) if prev_records else 0
    prev_ips = sum(m.get('unique_src_ips',0) for _,m in prev_records)
    tot = total_pkts or 1

    def proto_avg(key):
        vals = [m.get('protocols',{}).get(key,0)/max(m.get('total_packets',1),1)*100 for _,m in records]
        return (sum(vals)/len(vals) if vals else 0, min(vals) if vals else 0, max(vals) if vals else 0)
    tcp_avg,tcp_min,tcp_max = proto_avg('TCP')
    udp_avg,udp_min,udp_max = proto_avg('UDP')
    icmp_avg,icmp_min,icmp_max = proto_avg('ICMP')

    # Full month TCP+UDP
    mo_tcp, mo_udp = defaultdict(int), defaultdict(int)
    for _,m in records:
        for p,c in m.get('top_ports',{}).items(): mo_tcp[int(p)] += c
        for e in m.get('top_udp_ports',[]): mo_udp[e['port']] += e['packets']
    top10_tcp = sorted(mo_tcp.items(), key=lambda x:-x[1])[:10]
    top10_udp = sorted(mo_udp.items(), key=lambda x:-x[1])[:10]
    mo_tot = sum(mo_tcp.values()) or 1

    geo_pkts, geo_ips = defaultdict(int), defaultdict(int)
    asn_t = defaultdict(int)
    for _,m in records:
        for e in m.get('top_countries',[]): geo_pkts[e['country']] += e['packets']
        for e in m.get('top_countries_by_sources',[]): geo_ips[e['country']] += e.get('unique_ips',0)
        for e in m.get('top_asns_by_sources',[]): asn_t[e['asn']] += e.get('unique_ips',0)
    top10_geo = sorted(geo_pkts.items(), key=lambda x:-x[1])[:10]
    top10_asn = sorted(asn_t.items(), key=lambda x:-x[1])[:5]

    # Week data
    wk_data = defaultdict(lambda: {'pkts':0,'days':0,'anom':0,'ips':0})
    for d,m in records:
        dt = datetime.strptime(d,'%Y-%m-%d')
        wk = dt.isocalendar()[1]
        wk_data[wk]['pkts'] += m.get('total_packets',0)
        wk_data[wk]['ips']  += m.get('unique_src_ips',0)
        wk_data[wk]['days'] += 1
        if d in anom_dates: wk_data[wk]['anom'] += 1

    n_anom = len(anom_dates)
    obs_days = len(records)
    lines = []
    snippet_dir = os.path.dirname(out_path)
    def cmd(name, val):
        val_s = str(val)
        if '\n' in val_s:
            snip = os.path.join(snippet_dir, f'snip_{name}.tex')
            with open(snip, 'w') as sf:
                sf.write(f'\\newcommand{{\\{name}}}{{%\n{val_s}}}\n')
            lines.append(f'\\input{{{snip}}}')
        else:
            lines.append(f'\\newcommand{{\\{name}}}{{{val_s}}}')

    cmd('monthlabel', esc(year_month))
    cmd('generatedtime', datetime.now().strftime('%Y-%m-%d %H:%M'))
    cmd('statuscolor','alertred' if n_anom else 'okgreen')
    cmd('statusbg', 'alertbg'  if n_anom else 'okbg')
    cmd('statustext', f'{n_anom} ANOMALY DAY(S) IN {year_month}' if n_anom else f'NORMAL MONTH --- {year_month}')
    cmd('statusnote', esc(f'{n_anom} anomaly days out of {obs_days} observed.' if n_anom else f'All {obs_days} days within expected ranges.'))

    cmd('barchart', barchart(
        [m.get('total_packets',0) for _,m in records],
        [d for d,_ in records],
        W=15.5, H=2.5, anomaly_dates=anom_dates
    ))


    mr = f'Total Packets & {fmtn(total_pkts)} & {fmtn(prev_total)} & {delta_fmt(total_pkts,prev_total)} \\\\\n'
    mr += f'\\rowcolor{{lightbg}}Daily Average & {fmtn(daily_avg)} & {fmtn(prev_avg)} & {delta_fmt(daily_avg,prev_avg)} \\\\\n'
    mr += f'Total Unique IPs & {fmtn(total_ips)} & {fmtn(prev_ips)} & {delta_fmt(total_ips,prev_ips)} \\\\\n'
    prev_n_anom = prev_n_anom_count
    mr += f'\\rowcolor{{lightbg}}Observation Days & {obs_days} & {len(prev_records)} & {delta_fmt(obs_days, len(prev_records))} \\\\\n'
    mr += f'Anomaly Days & {n_anom} & {prev_n_anom} & {delta_fmt(n_anom, prev_n_anom)} \\\\\n'
    cmd('metricsrows', mr)


    pr = f'TCP & {fmtp(tcp_avg)} & {fmtp(tcp_min)} & {fmtp(tcp_max)} \\\\\n'
    pr += f'\\rowcolor{{lightbg}}UDP & {fmtp(udp_avg)} & {fmtp(udp_min)} & {fmtp(udp_max)} \\\\\n'
    pr += f'ICMP & {fmtp(icmp_avg)} & {fmtp(icmp_min)} & {fmtp(icmp_max)} \\\\\n'
    cmd('protorows', pr)


    wr = ''
    for i,wk in enumerate(sorted(wk_data.keys())):
        w = wk_data[wk]
        davg = w['pkts']//w['days'] if w['days'] else 0
        flag = f"{{\\color{{alertred}}{w['anom']} anomal{'y' if w['anom']==1 else 'ies'}}}" if w['anom'] else '{\\color{mutedgray}---}'
        wr += f"{altrow(i)}Week {wk} & {fmtn(w['pkts'])} & {fmtn(davg)} & {fmtn(w['ips'])} & {flag} \\\\\n"
    cmd('weekrows', wr)

    # TCP + UDP rows
    tcp_rows = ''
    for i,(port,cnt) in enumerate(top10_tcp):
        tcp_rows += f'{altrow(i)}{i+1} & {port} & {esc(pname(port))} & {fmtn(cnt)} & {fmtp(cnt/mo_tot*100)} \\\\\n'
    cmd('tcprows', tcp_rows)

    udp_rows = ''
    for i,(port,cnt) in enumerate(top10_udp):
        udp_rows += f'{altrow(i)}{i+1} & {port} & {esc(pname(port))} & {fmtn(cnt)} & {fmtp(cnt/mo_tot*100)} \\\\\n'
    cmd('udprows', udp_rows)

    geo_rows = ''
    for i,(cc,cnt) in enumerate(top10_geo):
        geo_rows += f'{altrow(i)}{i+1} & {esc(cc)} & {fmtn(cnt)} & {fmtp(cnt/tot*100)} & {fmtn(geo_ips.get(cc,0))} \\\\\n'
    cmd('georows', geo_rows)

    asn_rows = ''
    for i,(asn,cnt) in enumerate(top10_asn):
        raw = asn_names.get(asn, f'AS{asn}')
        raw = raw.split(',')[0].split(' - ')[-1].strip()
        asn_rows += f'{altrow(i)}{i+1} & AS{asn} & {esc(raw[:22])} & {fmtn(cnt)} \\\\\n'
    cmd('asnrows', asn_rows)

    # Data quality
    if gap:
        gaps_found = gap.get('gaps_found', 0)
        downtime_h = round(gap.get('total_gap_seconds', 0) / 3600, 1)
        total_secs = ndays * 86400
        uptime_pct = round((1 - gap.get('total_gap_seconds', 0) / total_secs) * 100, 1)
        qtxt = f'{gaps_found} gaps, {downtime_h}h downtime, {uptime_pct}\\% uptime'
        qcol = 'alertred' if gaps_found > 5 else 'mutedgray'
    else:
        qtxt = 'Gap analysis not available for this month.'
        qcol = 'mutedgray'
    cmd('qualitytext',  qtxt)
    cmd('qualitycolor', qcol)

    # Anomaly list
    if anom_details:
        arows = ''
        for i,a in enumerate(sorted(anom_details, key=lambda x:x['date'])):
            params = esc(', '.join(a.get('parameters_triggered',[])))
            arows += f'{altrow(i)}{esc(a["date"])} & {fmtn(a.get("total_packets",0))} & {params} \\\\\n'
        anom_block = (
            r'\vspace{3mm}' + '\n'
            r'{\footnotesize\bfseries\color{alertred} ANOMALY DAYS}\\[1mm]' + '\n'
            r'\begin{tabular}{L{26mm} R{20mm} L{100mm}}' + '\n'
            r'\toprule' + '\n'
            r'\rowcolor{headerdk}{\color{white}\bfseries\small Date} & '
            r'{\color{white}\bfseries\small Packets} & '
            r'{\color{white}\bfseries\small Parameters} \\' + '\n'
            r'\midrule' + '\n' + arows +
            r'\bottomrule' + '\n' + r'\end{tabular}'
        )
    else:
        anom_block = ''
    cmd('anomalydetail', anom_block)

    with open(out_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')


#Compile
def compile_pdf(template, data_file, output_pdf):
    """Inject data path into template, compile to PDF."""
    with open(template) as f:
        tex = f.read()
    tex = tex.replace('DATA_FILE', data_file.replace('\\', '/'))
    tex_path = output_pdf.replace('.pdf', '.tex')
    with open(tex_path, 'w') as f:
        f.write(tex)
    odir = os.path.dirname(tex_path)
    for _ in range(2):
        subprocess.run(['pdflatex', '-interaction=nonstopmode',
                        '-output-directory', odir, tex_path],
                       capture_output=True)
    pdf = tex_path.replace('.tex', '.pdf')
    if os.path.exists(pdf):
        for ext in ['.aux', '.log', '.out', '.tex']:
            p = tex_path.replace('.tex', ext)
            if os.path.exists(p): os.remove(p)
        return pdf
    return None


#Main
def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 ibr_report.py daily <metrics_file>")
        print("  python3 ibr_report.py weekly <end_date>")
        print("  python3 ibr_report.py monthly <year_month>")
        sys.exit(1)

    cmd = sys.argv[1]
    arg = sys.argv[2]
    asn_names = load_asn_names()

    if cmd == 'daily':
        date = Path(arg).stem
        out_dir = os.path.join(BASE, 'reports', 'daily')
        os.makedirs(out_dir, exist_ok=True)
        data_f = os.path.join(out_dir, f'{date}_data.tex')
        out_pdf = os.path.join(out_dir, f'{date}_report.pdf')
        tmpl = os.path.join(TMPL_DIR, 'daily_report.tex')
        print(f"Building daily report: {date}")
        write_daily_data(arg, asn_names, data_f)
        compile_pdf(tmpl, data_f, out_pdf)

    elif cmd == 'weekly':
        out_dir = os.path.join(BASE, 'reports', 'weekly')
        os.makedirs(out_dir, exist_ok=True)
        label = f"weekly_{arg}"
        data_f = os.path.join(out_dir, f'{label}_data.tex')
        out_pdf = os.path.join(out_dir, f'{label}.pdf')
        tmpl = os.path.join(TMPL_DIR, 'weekly_report.tex')
        write_weekly_data(arg, asn_names, data_f)
        compile_pdf(tmpl, data_f, out_pdf)

    elif cmd == 'monthly':
        out_dir = os.path.join(BASE, 'reports', 'monthly')
        os.makedirs(out_dir, exist_ok=True)
        data_f = os.path.join(out_dir, f'monthly_{arg}_data.tex')
        out_pdf = os.path.join(out_dir, f'monthly_{arg}.pdf')
        tmpl = os.path.join(TMPL_DIR, 'monthly_report.tex')
        print(f"Building monthly report: {arg}")
        write_monthly_data(arg, asn_names, data_f)
        compile_pdf(tmpl, data_f, out_pdf)


if __name__ == '__main__':
    main()