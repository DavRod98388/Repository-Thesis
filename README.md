Bachelor thesis 2026

This repository includes source code, LaTeX templates and examples of reports for a automated analyzis and reporting system for Internet Background Radiation (IBR) captured by one of SANREN's /24 network telescopes. 

FILE STRUCTURE: 

- `python/` - Core code for the analysis pipeline
  - `daily_parser.py` - PCAP parser that extracts daily metrics
  - `anomaly_detector.py` - Anomaly detection across five parameters
  - `report.py` - LaTeX report generator (daily, weekly, monthly)
  - `gap_detector.py` - Monthly gap detection across PCAP boundaries
  - `rrd_update.py` - Updates RRD time-series databases
  - `metrics_adapter.py` - Helper module for the report generator

- `scripts/` - Shell scripts for orchestration
  - `run_daily.sh` - Daily pipeline (parsing, anomalies, report)
  - `setup_rrd.sh` - Creates the RRD databases

- `templates/` - LaTeX templates
  - `daily_report.tex`
  - `weekly_report.tex`
  - `monthly_report.tex`

- `examples/` - Example PDF reports


EXPECTATIONS: 

- Ubuntu 24.04 LTS (Or another Linux-distribution)
- Python 3.10 or newer 
- Python-pakker: `dpkt`, `geoip2`
- LaTeX med `pdflatex` (TeX Live is recommended)
- MaxMind GeoLite2-databases (Country og ASN)
- `rrdtool`

INSTALATION: 
1. Clone the repository
- git clone https://github.com/DavRod98388/Repository-Thesis cd Repository-Thesis

2. Install system dependencies: 
- Sudo apt update
- sudo apt install python3 python3-pip rrdtool texlive-full

3. Install Python packages:
- pip install dpkt geoip2 --break-system-packages

4. Download MaxMind GeoLite2 Databases:
   -Create a free account at https://www.maxmind.com/en/geolite2/signup
   - Download `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb`
   - Place them in `lib/maxmind/`
5. Initialise RRD databases:
   - ./scripts/setup_rrd.sh


AUTOMATION: 

The pipeline is designed to run nightly at 02:00 via cron.
To enable automatic execution add the following line: 

0 2 * * * /home/<user>/ibr-analyst/scripts/run_daily.sh

Replace `<user>` with the actual username.

OUTPUT: 

The pipeline produces the following files:

arsing output (`data/parsed/`):**
- `daily/YYYY-MM-DD.json` - Daily metrics (packets, protocols, ports, geo, ASN)
- `ip_activity/YYYY-MM-DD.csv` - Per-IP activity breakdown
- `ip_sets/YYYY-MM-DD.pkl.gz` - IP set for next-day churn calculation

Analysis output:**
- `data/parsed/anomalies_2025.json` - Accumulated anomaly log
- `data/parsed/gaps/YYYY-MM.json` - Monthly gap detection results

Time-series databases (`rrd/`):**
- `packets.rrd`, `protocols.rrd`, `ports.rrd`, `port_concentration.rrd`, `churn.rrd`

Reports (`reports/`):**
- `daily/YYYY-MM-DD_report.pdf`
- `weekly/weekly_YYYY-MM-DD.pdf`
- `monthly/monthly_YYYY-MM.pdf`

logs (`logs/`):**
- `daily_YYYY-MM-DD.log` - Pipeline execution log


David Rød, bachelor student at Noroff University College.  
Supervisor: Barry Irwin.
