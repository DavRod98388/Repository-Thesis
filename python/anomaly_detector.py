#!/usr/bin/env python3

import json
import os
import sys
import argparse
import math
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict



EWMA_WINDOW        = 7  
EWMA_ALPHA         = 0.3
VOLUME_THRESHOLD   = 0.20
MAD_MULTIPLIER     = 3.0
PROTO_WINDOW       = 30 
PROTO_THRESHOLD_PP = 5.0 
PORT_WINDOW        = 30 
PORT_TOP_N         = 5 
PORT_THRESHOLD_PP  = 10.0 
CHURN_STD_MULT     = 2.0



# Data loading
def load_daily_json(date_str, data_dir="data/parsed/daily"):
    path = os.path.join(data_dir, f"{date_str}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)

#Load and return sorted lists
def load_all_daily(data_dir="data/parsed/daily"):
    records = []
    for fname in sorted(os.listdir(data_dir)):
        if not fname.endswith(".json"):
            continue
        date_str = fname.replace(".json", "")
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            continue
        data = load_daily_json(date_str, data_dir)
        if data:
            records.append((date_str, data))
    return records

#Load ip set for given date 
def load_ip_activity(date_str, data_dir="data/parsed/ip_activity"):
    import gzip, pickle

    pkl_path = os.path.join("data/parsed/ip_sets", f"{date_str}.pkl.gz")
    if os.path.exists(pkl_path):
        try:
            with gzip.open(pkl_path, 'rb') as f:
                return pickle.load(f)
        except Exception:
            pass

    # Fall back to CSV 
    path = os.path.join(data_dir, f"{date_str}.csv")
    if not os.path.exists(path):
        return set()

    ips = set()
    with open(path) as f:
        f.readline()  
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 2:
                ips.add(parts[1])
    return ips



# Returns list of EWMA values same length as input.
def compute_ewma(values, alpha=EWMA_ALPHA):
    if not values:
        return []
    ewma = [values[0]]
    for v in values[1:]:
        ewma.append(alpha * v + (1 - alpha) * ewma[-1])
    return ewma


def compute_mad(values):

    if not values:
        return 0.0
    median = sorted(values)[len(values) // 2]
    deviations = [abs(v - median) for v in values]
    return sorted(deviations)[len(deviations) // 2]


def rolling_mean_std(values, window):
    if not values:
        return 0.0, 0.0
    subset = values[-window:]
    mean = sum(subset) / len(subset)
    variance = sum((v - mean) ** 2 for v in subset) / len(subset)
    return mean, math.sqrt(variance)


def quarterly_mean_std(date_str, churn_series):
    date = datetime.strptime(date_str, "%Y-%m-%d")
    quarter = (date.month - 1) // 3 + 1

    values = []
    for ds, churn in churn_series:
        d = datetime.strptime(ds, "%Y-%m-%d")
        if d.year == date.year and (d.month - 1) // 3 + 1 == quarter:
            values.append(churn)

    if len(values) < 3:
        return 0.0, 1.0  
    mean = sum(values) / len(values)
    std = math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))
    return mean, std



# Detection functions

#Packet volume 
def detect_volume_anomaly(date_str, all_records):

    dates = [r[0] for r in all_records]
    volumes = [r[1].get("total_packets", 0) for r in all_records]

    if date_str not in dates:
        return None

    idx = dates.index(date_str)
    if idx < EWMA_WINDOW:
        return None

    
    history_volumes = volumes[:idx]
    ewma_values = compute_ewma(history_volumes)
    baseline = ewma_values[-1]

    today = volumes[idx]
    if baseline == 0:
        return None

    deviation = (today - baseline) / baseline

    if abs(deviation) > VOLUME_THRESHOLD:
        return {
            "parameter": "packet_volume",
            "value": today,
            "baseline": round(baseline, 0),
            "deviation_pct": round(deviation * 100, 1),
            "threshold_pct": VOLUME_THRESHOLD * 100,
            "direction": "spike" if deviation > 0 else "drop",
        }
    return None

#Source Count
def detect_source_count_anomaly(date_str, all_records):

    dates = [r[0] for r in all_records]
    counts = [r[1].get("unique_src_ips", 0) for r in all_records]

    if date_str not in dates:
        return None

    idx = dates.index(date_str)
    if idx < 14:
        return None 

    history = counts[:idx]
    median = sorted(history)[len(history) // 2]
    mad = compute_mad(history)

    if mad == 0:
        return None

    today = counts[idx]
    deviation = abs(today - median)

    if deviation > MAD_MULTIPLIER * mad:
        return {
            "parameter": "source_count",
            "value": today,
            "median": median,
            "mad": round(mad, 1),
            "deviation_mad_units": round(deviation / mad, 2),
            "threshold_mad_units": MAD_MULTIPLIER,
            "direction": "spike" if today > median else "drop",
        }
    return None

#Protocol distributon
def detect_protocol_anomaly(date_str, all_records):

    dates = [r[0] for r in all_records]

    if date_str not in dates:
        return None

    idx = dates.index(date_str)
    if idx < PROTO_WINDOW:
        return None

    def get_proto_shares(record):
        protos = record.get("protocols", {})
        total = sum(
            (v["packets"] if isinstance(v, dict) else v)
            for v in protos.values()
        )
        if total == 0:
            return {}
        shares = {}
        for proto, v in protos.items():
            packets = v["packets"] if isinstance(v, dict) else v
            shares[proto] = (packets / total) * 100
        return shares

    # Building a rolling baseline
    history_records = [r[1] for r in all_records[max(0, idx - PROTO_WINDOW):idx]]
    proto_history = defaultdict(list)
    for rec in history_records:
        shares = get_proto_shares(rec)
        for proto, share in shares.items():
            proto_history[proto].append(share)

    today_shares = get_proto_shares(all_records[idx][1])
    deviations = []

    for proto in ["TCP", "UDP", "ICMP"]:
        if proto not in proto_history or proto not in today_shares:
            continue
        hist = proto_history[proto]
        mean = sum(hist) / len(hist)
        deviation_pp = abs(today_shares[proto] - mean)
        if deviation_pp > PROTO_THRESHOLD_PP:
            deviations.append({
                "protocol": proto,
                "today_pct": round(today_shares[proto], 2),
                "baseline_mean_pct": round(mean, 2),
                "deviation_pp": round(deviation_pp, 2),
            })

    if deviations:
        return {
            "parameter": "protocol_distribution",
            "deviations": deviations,
            "threshold_pp": PROTO_THRESHOLD_PP,
        }
    return None

#Port Concentration 
def detect_port_concentration_anomaly(date_str, all_records):

    dates = [r[0] for r in all_records]

    if date_str not in dates:
        return None

    idx = dates.index(date_str)
    if idx < PORT_WINDOW:
        return None

    def top_n_share(record, n=PORT_TOP_N):
        ports = record.get("top_tcp_ports", [])
        if not ports:
            return 0.0
        tcp_total = record.get("protocols", {}).get("TCP", {})
        if isinstance(tcp_total, dict):
            tcp_total = tcp_total.get("packets", 0)
        if tcp_total == 0:
            return 0.0
        top_n = sum(p["packets"] for p in ports[:n])
        return (top_n / tcp_total) * 100

    history = [top_n_share(r[1]) for r in all_records[max(0, idx - PORT_WINDOW):idx]]
    history = [v for v in history if v > 0]

    if not history:
        return None

    mean = sum(history) / len(history)
    today = top_n_share(all_records[idx][1])
    deviation_pp = today - mean

    if deviation_pp > PORT_THRESHOLD_PP:
        today_ports = all_records[idx][1].get("top_tcp_ports", [])
        return {
            "parameter": "port_concentration",
            "top_n": PORT_TOP_N,
            "today_share_pct": round(today, 2),
            "baseline_mean_pct": round(mean, 2),
            "deviation_pp": round(deviation_pp, 2),
            "threshold_pp": PORT_THRESHOLD_PP,
            "top_ports": [
                {"port": p["port"], "packets": p["packets"]}
                for p in today_ports[:PORT_TOP_N]
            ],
        }
    return None

#Churn Rate
def detect_churn_anomaly(date_str, all_records, churn_series):

    # Find today's churn value
    today_churn = None
    for ds, churn in churn_series:
        if ds == date_str:
            today_churn = churn
            break

    if today_churn is None:
        return None

    mean, std = quarterly_mean_std(date_str, churn_series)
    threshold = mean + CHURN_STD_MULT * std

    if today_churn > threshold:
        return {
            "parameter": "churn_rate",
            "value": round(today_churn, 4),
            "quarterly_mean": round(mean, 4),
            "quarterly_std": round(std, 4),
            "threshold": round(threshold, 4),
            "std_multiples": round(CHURN_STD_MULT, 1),
        }
    return None


# Churn computation


def compute_churn_series(all_records, ip_activity_dir="data/parsed/ip_activity"):
    print("Computing churn series")

    seen_ever = set()
    churn_series = []

    for date_str, record in all_records:
        total_ips = record.get("unique_src_ips", 0)
        if total_ips == 0:
            continue

        today_ips = load_ip_activity(date_str, ip_activity_dir)

        if not today_ips:
            churn_series.append((date_str, None))
            continue

        new_ips = today_ips - seen_ever
        churn_rate = len(new_ips) / len(today_ips) if today_ips else 0.0

        seen_ever.update(today_ips)
        churn_series.append((date_str, churn_rate))

    valid = [(d, c) for d, c in churn_series if c is not None]
    print(f"  Computed churn for {len(valid)} days")
    return churn_series



# Main detection engine
#Runs all five for given date 

def analyse_day(date_str, all_records, churn_series):
    alerts = []

    r1 = detect_volume_anomaly(date_str, all_records)
    if r1:
        alerts.append(r1)

    r2 = detect_source_count_anomaly(date_str, all_records)
    if r2:
        alerts.append(r2)

    r3 = detect_protocol_anomaly(date_str, all_records)
    if r3:
        alerts.append(r3)

    r4 = detect_port_concentration_anomaly(date_str, all_records)
    if r4:
        alerts.append(r4)

    r5 = detect_churn_anomaly(date_str, all_records, churn_series)
    if r5:
        alerts.append(r5)

    if not alerts:
        return None

    # Find today's packet count for context
    record = next((r[1] for r in all_records if r[0] == date_str), {})

    return {
        "date": date_str,
        "total_packets": record.get("total_packets", 0),
        "unique_ips": record.get("unique_src_ips", 0),
        "alert_count": len(alerts),
        "parameters_triggered": [a["parameter"] for a in alerts],
        "alerts": alerts
    }


def run_detection(dates=None, data_dir="data/parsed/daily",
                  ip_dir="data/parsed/ip_activity", output_file=None):

    print("=" * 70)
    print("IBR ANOMALY DETECTOR")
    print("=" * 70)

    # Load all daily data
    print(f"\nLoading daily metrics from {data_dir}...")
    all_records = load_all_daily(data_dir)
    print(f"  Loaded {len(all_records)} days")

    if not all_records:
        print("ERROR: No daily JSON files found. Run the parser first.")
        return []

    # Compute churn series once up front
    churn_series = compute_churn_series(all_records, ip_dir)

    # Determine which dates to analyse
    if dates:
        target_dates = dates
    else:
        target_dates = [r[0] for r in all_records]

    print(f"\nAnalysing {len(target_dates)} days...")
    print("-" * 70)

    anomalies = []
    for date_str in target_dates:
        result = analyse_day(date_str, all_records, churn_series)
        if result:
            params = ", ".join(result["parameters_triggered"])
            print(f"  ANOMALY  {date_str}  [{result['alert_count']} parameter(s): {params}]")
            anomalies.append(result)

    print("-" * 70)
    print(f"\nSummary: {len(anomalies)} anomaly days found out of {len(target_dates)} analysed")

    # Parameter breakdown
    param_counts = defaultdict(int)
    for a in anomalies:
        for p in a["parameters_triggered"]:
            param_counts[p] += 1

    if param_counts:
        print("\nParameter trigger counts:")
        for param, count in sorted(param_counts.items(), key=lambda x: -x[1]):
            print(f"  {param:30s}: {count}")

    # Save output
    output = {
        "generated": datetime.now().isoformat(),
        "days_analysed": len(target_dates),
        "anomaly_days": len(anomalies),
        "thresholds": {
            "packet_volume_ewma_pct": VOLUME_THRESHOLD * 100,
            "source_count_mad_multiplier": MAD_MULTIPLIER,
            "protocol_distribution_pp": PROTO_THRESHOLD_PP,
            "port_concentration_pp": PORT_THRESHOLD_PP,
            "churn_std_multiplier": CHURN_STD_MULT,
        },
        
        "anomalies": anomalies
    }

    if output_file is None:
        output_file = "data/parsed/anomalies_2025.json"

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved: {output_file}")

    return anomalies


def main():
    parser = argparse.ArgumentParser(
        description="Multi-parameter IBR anomaly detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,

    )
    parser.add_argument("--date", help="Analyse a single date (YYYY-MM-DD)")
    parser.add_argument("--output", help="Output JSON file path")
    parser.add_argument(
        "--data-dir", default="data/parsed/daily",
        help="Directory containing daily JSON files"
    )
    parser.add_argument(
        "--ip-dir", default="data/parsed/ip_activity",
        help="Directory containing per-IP activity CSVs"
    )
    args = parser.parse_args()

    dates = [args.date] if args.date else None

    run_detection(
        dates=dates,
        data_dir=args.data_dir,
        ip_dir=args.ip_dir,
        output_file=args.output
    )


if __name__ == "__main__":
    main()