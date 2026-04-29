#!/usr/bin/env python3

from datetime import datetime

def adapt_metrics(metrics):

    adapted = dict(metrics)

    # unique_sources
    if 'unique_ips' in metrics and 'unique_sources' not in metrics:
        adapted['unique_sources'] = metrics['unique_ips']

    # end_time
    if 'end_time' not in metrics and 'date' in metrics:
        try:
            dt = datetime.strptime(metrics['date'], '%Y-%m-%d')
            adapted['end_time'] = int(dt.timestamp())
        except ValueError:
            pass

    # protocols
    if 'protocols' in metrics:
        flat = {}
        for proto, val in metrics['protocols'].items():
            flat[proto] = val.get('packets', 0) if isinstance(val, dict) else val
        adapted['protocols'] = flat

    # top_ports
    if 'top_tcp_ports' in metrics and 'top_ports' not in metrics:
        adapted['top_ports'] = {
            str(entry['port']): entry['packets']
            for entry in metrics.get('top_tcp_ports', [])
        }
    if 'avg_packet_size' not in metrics and 'packet_size_stats' in metrics:
        adapted['avg_packet_size'] = metrics['packet_size_stats'].get('avg', 0)

    return adapted