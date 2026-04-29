#!/usr/bin/env python3

import subprocess
import json
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from metrics_adapter import adapt_metrics


def load_churn(date_str, parsed_dir):

    anomaly_file = os.path.join(parsed_dir, 'anomalies_daily.json')
    if os.path.exists(anomaly_file):
        try:
            with open(anomaly_file) as f:
                data = json.load(f)
            for a in data.get('anomalies', []):
                if a.get('date') == date_str:
                    for alert in a.get('alerts', []):
                        if alert.get('parameter') == 'churn_rate':
                            return alert.get('value', 0) * 100
        except Exception:
            pass

    csv_path = os.path.join(parsed_dir, 'ip_activity', f'{date_str}.csv')
    if not os.path.exists(csv_path):
        return None
    return None


def top5_concentration(metrics):

    top_ports = metrics.get('top_ports', {})
    tcp_total = metrics.get('protocols', {}).get('TCP', 0)
    if not top_ports or not tcp_total:
        return 0.0
    top5_sum = sum(
        count for _, count in
        sorted(top_ports.items(), key=lambda x: x[1], reverse=True)[:5]
    )
    return (top5_sum / tcp_total * 100)


def rrd_update(cmd, label):
    try:
        result = subprocess.run(
            cmd, check=True, capture_output=True, text=True
        )
        print(f" {label}")
    except subprocess.CalledProcessError as e:
        print(f" {label}: {e.stderr.strip()}")


def update_rrd(metrics_file, rrd_dir):
    print(f"Reading: {metrics_file}")

    try:
        with open(metrics_file) as f:
            raw = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {metrics_file}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"ERROR: Invalid JSON: {metrics_file}")
        sys.exit(1)

    metrics  = adapt_metrics(raw)
    date_str = metrics.get('date', '')

    # Derive timestamp from date string (midnight UTC)
    if date_str:
        try:
            dt = datetime.strptime(date_str, '%Y-%m-%d')
            timestamp = int(dt.timestamp())
        except ValueError:
            timestamp = int(datetime.now().timestamp())
    elif 'end_time' in metrics:
        dt = datetime.fromtimestamp(metrics['end_time'])
        dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        timestamp = int(dt.timestamp())
    else:
        timestamp = int(datetime.now().timestamp())

    print(f"Date: {date_str}  Timestamp: {timestamp}")
    print(f"Updating RRD databases...")

    # packets.rrd
    total_packets = metrics.get('total_packets', 0)
    unique_ips    = metrics.get('unique_sources', 0)
    rrd_update(
        ['rrdtool', 'update', os.path.join(rrd_dir, 'packets.rrd'),
         f'{timestamp}:{total_packets}:{unique_ips}'],
        f'packets.rrd  (packets={total_packets:,}  unique_ips={unique_ips:,})'
    )

    #protocols.rrd
    protos= metrics.get('protocols', {})
    total = metrics['total_packets'] or 1
    tcp_pct = protos.get('TCP',  0) / total * 100
    udp_pct = protos.get('UDP',  0) / total * 100
    icmp_pct = protos.get('ICMP', 0) / total * 100
    rrd_update(
        ['rrdtool', 'update', os.path.join(rrd_dir, 'protocols.rrd'),
         f'{timestamp}:{tcp_pct:.2f}:{udp_pct:.2f}:{icmp_pct:.2f}'],
        f'protocols.rrd  (TCP={tcp_pct:.1f}%  UDP={udp_pct:.1f}%  ICMP={icmp_pct:.1f}%)'
    )

    #ports.rrd
    top_ports = metrics.get('top_ports', {})
    port_list = sorted(top_ports.items(), key=lambda x: x[1], reverse=True)[:5]
    port_counts = [str(c) for _, c in port_list]
    while len(port_counts) < 5:
        port_counts.append('0')
    rrd_update(
        ['rrdtool', 'update', os.path.join(rrd_dir, 'ports.rrd'),
         f'{timestamp}:{":".join(port_counts)}'],
        f'ports.rrd  (top ports: {", ".join(port_counts)})'
    )

    #port_concentration.rrd

    conc = top5_concentration(metrics)
    rrd_update(
        ['rrdtool', 'update', os.path.join(rrd_dir, 'port_concentration.rrd'),
         f'{timestamp}:{conc:.2f}'],
        f'port_concentration.rrd  (top5_share={conc:.1f}%)'
    )

    #churn.rrd
    parsed_dir = os.path.dirname(os.path.dirname(metrics_file))
    churn = load_churn(date_str, parsed_dir)
    if churn is not None:
        rrd_update(
            ['rrdtool', 'update', os.path.join(rrd_dir, 'churn.rrd'),
             f'{timestamp}:{churn:.2f}'],
            f'churn.rrd  (churn={churn:.1f}%)'
        )
    else:
        print(f"  - churn.rrd  (skipped no churn data for {date_str})")

    print(f"\nRRD update complete for {date_str}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 rrd_update.py <daily_json> [rrd_directory]")
        print("Example: python3 rrd_update.py data/parsed/daily/2025-01-23.json")
        sys.exit(1)

    metrics_file = sys.argv[1]
    rrd_dir = sys.argv[2] if len(sys.argv) >= 3 else \
        os.path.join(os.path.expanduser('~'), 'ibr-analyst', 'rrd')

    if not os.path.isdir(rrd_dir):
        print(f"ERROR: RRD directory not found: {rrd_dir}")
        print("Run scripts/setup_rrd.sh first")
        sys.exit(1)

    required = ['packets.rrd', 'protocols.rrd', 'ports.rrd',
                'port_concentration.rrd', 'churn.rrd']
    missing = [r for r in required
               if not os.path.isfile(os.path.join(rrd_dir, r))]
    if missing:
        print(f"ERROR: Missing RRD files: {missing}")
        print("Run scripts/setup_rrd.sh first")
        sys.exit(1)

    update_rrd(metrics_file, rrd_dir)