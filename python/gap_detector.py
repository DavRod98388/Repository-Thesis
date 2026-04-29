#!/usr/bin/env python3

import dpkt
import os
import sys
import json
import tarfile
import argparse
import calendar
from datetime import datetime, timedelta
from pathlib import Path

DEFAULT_THRESHOLD = 900   # seconds


#PCAP extraction
def extract_daily_pcap(date_str, base_dir):

    date_obj = datetime.strptime(date_str, '%Y-%m-%d')
    pcap_filename = date_obj.strftime('%Y%m%d.pcap')
    year = date_obj.year
    quarter = (date_obj.month - 1) // 3 + 1


    standalone = os.path.join(base_dir, 'data', 'raw', 'daily', pcap_filename)
    if os.path.exists(standalone):
        return standalone, False

    # Quarterly archive
    archive = os.path.join(
        base_dir, 'data', 'raw', 'archived',
        f'Q{quarter}_{year}_daily.tar.gz'
    )
    if not os.path.exists(archive):
        return None, False

    temp_path = f"/tmp/{pcap_filename}"
    try:
        with tarfile.open(archive, 'r:gz') as tar:
            member = None
            for path_attempt in [
                pcap_filename,
                f"data/raw/daily/{pcap_filename}",
                f"data/raw/daily/{year}Q{quarter}/{pcap_filename}",
            ]:
                try:
                    member = tar.getmember(path_attempt)
                    break
                except KeyError:
                    continue

            if member is None:
                return None, False

            with tar.extractfile(member) as src:
                with open(temp_path, 'wb') as dst:
                    dst.write(src.read())

        return temp_path, True

    except Exception as e:
        print(f"  Warning: could not extract {pcap_filename}: {e}")
        return None, False


#Core gap detection

def detect_monthly_gaps(year_month, base_dir, threshold=DEFAULT_THRESHOLD):
    """
    Read all daily PCAPs for the month sequentially.
    Maintains timestamp continuity across midnight boundaries.
    Returns gap report dict matching Barry's output format.
    """
    year, month   = int(year_month[:4]), int(year_month[5:7])
    _, days_count = calendar.monthrange(year, month)
    dates = [
        datetime(year, month, d).strftime('%Y-%m-%d')
        for d in range(1, days_count + 1)
    ]

    # The missing days
    known_missing = {'2025-01-31', '2025-02-09'}

    gaps            = []
    prev_ts         = None
    first_ts        = None
    last_ts         = None
    total_packets   = 0
    total_gap_sec   = 0
    days_present    = []
    days_missing    = []

    print(f"\nMonthly gap detection: {year_month}")
    print(f"Threshold: {threshold} seconds")
    print(f"Days in month: {days_count}")
    print()

    for date_str in dates:
        if date_str in known_missing:
            print(f"  [skip]   {date_str}  known missing day")
            continue

        print(f"  [scan]   {date_str}", end=' ', flush=True)

        pcap_path, needs_cleanup = extract_daily_pcap(date_str, base_dir)

        if pcap_path is None:
            print(" MISSING")
            days_missing.append(date_str)
            if prev_ts is not None:
                gap_start = datetime.fromtimestamp(prev_ts).strftime('%Y-%m-%d %H:%M:%S.%f')
                gap_end   = f"{date_str} 00:00:00.000000"
                gaps.append({
                    'gap_number':    len(gaps) + 1,
                    'start':         gap_start,
                    'end':           gap_end,
                    'gap_seconds':   86400,
                    'packet_number': total_packets,
                    'note':          'Missing PCAP file',
                })
                total_gap_sec += 86400
            continue

        days_present.append(date_str)
        day_packets = 0

        try:
            with open(pcap_path, 'rb') as f:
                try:
                    pcap = dpkt.pcap.Reader(f)
                except Exception as e:
                    print(f" ERROR ({e})")
                    if needs_cleanup:
                        os.remove(pcap_path)
                    continue

                for ts, buf in pcap:
                    total_packets += 1
                    day_packets   += 1

                    if first_ts is None:
                        first_ts = ts

                    if prev_ts is not None:
                        gap_len = ts - prev_ts
                        if gap_len >= threshold:
                            gap = {
                                'gap_number':    len(gaps) + 1,
                                'start':         datetime.fromtimestamp(prev_ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                                'end':           datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f'),
                                'gap_seconds':   round(gap_len, 3),
                                'packet_number': total_packets,
                            }
                            gaps.append(gap)
                            total_gap_sec += gap_len

                    prev_ts = ts
                    last_ts = ts

        finally:
            if needs_cleanup and os.path.exists(pcap_path):
                os.remove(pcap_path)

        print(f" {day_packets:,} packets")

    # Build result
    if first_ts is None:
        print("\nERROR: No data found for this month")
        return None

    duration_start = datetime.fromtimestamp(first_ts).strftime('%Y-%m-%d %H:%M:%S.%f')
    duration_end   = datetime.fromtimestamp(last_ts).strftime('%Y-%m-%d %H:%M:%S.%f')
    pct_missing    = total_gap_sec / (days_count * 86400) * 100

    # Quality rating
    if total_gap_sec == 0:
        quality = 'COMPLETE'
    elif total_gap_sec < 3600:
        quality = 'GOOD'
    elif total_gap_sec < 14400:
        quality = 'PARTIAL'
    else:
        quality = 'POOR'

    return {
        'month': year_month,
        'threshold_seconds': threshold,
        'days_expected': days_count,
        'days_present': len(days_present),
        'days_missing': days_missing,
        'uptime_pct': round(len(days_present) / days_count * 100, 1),
        'duration_start': duration_start,
        'duration_end': duration_end,
        'total_packets': total_packets,
        'gaps_found': len(gaps),
        'total_gap_seconds': round(total_gap_sec),
        'pct_month_missing': round(pct_missing, 2),
        'quality': quality,
        'gaps': gaps,
    }


# Output helpers

def print_report(result):
    """Print gap report matching Barry's format."""
    print()
    print(f"# Month:{result['month']}")
    print(f"# Gap threshold: {result['threshold_seconds']} seconds")
    print(f"# Duration: {result['duration_start']}  ->  {result['duration_end']}")
    print(f"# Days:{result['days_present']}/{result['days_expected']} present")
    print(f"# Packets: {result['total_packets']:,}")
    print(f"# Gaps found: {result['gaps_found']}")
    print(f"# Secs missing: {result['total_gap_seconds']:,}  ({result['pct_month_missing']:.2f}% of month)")
    print(f"# Quality:{result['quality']}")

    if result['days_missing']:
        print(f"# Missing days: {', '.join(result['days_missing'])}")

    if result['gaps']:
        print()
        print(f"# {'Gap':<4} {'Start':<34} {'End':<34} {'Gap(s)':>8} {'Pkt#':>12}")
        for g in result['gaps']:
            note = f"  [{g.get('note','')}]" if g.get('note') else ''
            print(
                f"  {g['gap_number']:<4} "
                f"{g['start']:<34} -> "
                f"{g['end']:<34} "
                f"{g['gap_seconds']:>8.0f} "
                f"{g['packet_number']:>12,}"
                f"{note}"
            )
    else:
        print()
        print("  No gaps detected. Data appears complete.")
    print()


def save_result(result, base_dir):
    """Save result to data/parsed/gaps/YYYY-MM.json"""
    out_dir = os.path.join(base_dir, 'data', 'parsed', 'gaps')
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"{result['month']}.json")
    with open(out_file, 'w') as f:
        json.dump(result, f, indent=2)
    return out_file


def load_gap_result(year_month, base_dir=None):
    if base_dir is None:
        base_dir = os.path.join(os.path.expanduser('~'), 'ibr-analyst')
    path = os.path.join(base_dir, 'data', 'parsed', 'gaps', f"{year_month}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


#CLI

def main():
    parser = argparse.ArgumentParser(
        description='Monthly PCAP gap detector for IBR analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 gap_detector.py month 2025-05
  python3 gap_detector.py month 2025-01 --threshold 900
  python3 gap_detector.py month 2025-08 --summary
  python3 gap_detector.py all              # all 12 months of 2025
        """
    )
    parser.add_argument('--month', metavar='YYYY-MM',
                        help='Month to analyse')
    parser.add_argument('--all', action='store_true',
                        help='Analyse all months in 2025')
    parser.add_argument('--threshold', type=int, default=DEFAULT_THRESHOLD,
                        help=f'Gap threshold in seconds (default: {DEFAULT_THRESHOLD})')
    parser.add_argument('--summary', action='store_true',
                        help='Print report only, skip if already done')
    parser.add_argument('--force', action='store_true',
                        help='Re-run even if result already exists')
    args = parser.parse_args()

    base_dir = os.path.join(os.path.expanduser('~'), 'ibr-analyst')

    months = []
    if args.all:
        months = [f'2025-{m:02d}' for m in range(1, 13)]
    elif args.month:
        months = [args.month]
    else:
        parser.print_help()
        sys.exit(1)

    for year_month in months:
        # Check for existing result
        existing = load_gap_result(year_month, base_dir)
        if existing and not args.force:
            print(f"\nGap analysis already exists for {year_month} (use force to rerun)")
            print_report(existing)
            continue

        result = detect_monthly_gaps(year_month, base_dir, args.threshold)
        if result is None:
            continue

        print_report(result)
        out_file = save_result(result, base_dir)
        print(f"Saved: {out_file}")


if __name__ == '__main__':
    main()