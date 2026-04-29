#!/bin/bash

set -e

BASE_DIR="$HOME/ibr-analyst"
PYTHON_DIR="$BASE_DIR/python"
RRD_DIR="$BASE_DIR/rrd"
REPORTS_DIR="$BASE_DIR/reports/daily"
LOG_DIR="$BASE_DIR/logs"
PARSED_DIR="$BASE_DIR/data/parsed"
ANOMALY_FILE="$PARSED_DIR/anomalies_daily.json"

mkdir -p "$LOG_DIR" "$REPORTS_DIR"


if [ -n "$1" ]; then
    DATE="$1"
else
    # Default to yesterday
    DATE=$(date -d "yesterday" +%Y-%m-%d 2>/dev/null || date -v-1d +%Y-%m-%d)
fi

# Validate date format
if ! [[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "ERROR: Invalid date format. Use YYYY-MM-DD"
    exit 1
fi

LOG_FILE="$LOG_DIR/daily_${DATE}.log"


# Logging


log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $@" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $@" | tee -a "$LOG_FILE" >&2
}


log "Daily IBR Pipeline $DATE"


for script in \
    "$PYTHON_DIR/daily_parser.py" \
    "$PYTHON_DIR/rrd_update.py" \
    "$PYTHON_DIR/anomaly_detector.py" \
    "$PYTHON_DIR/report.py"; do
    if [ ! -f "$script" ]; then
        log_error "Missing script: $script"
        exit 1
    fi
done

if [ ! -d "$RRD_DIR" ]; then
    log_error "RRD directory not found. Run scripts/setup_rrd.sh first."
    exit 1
fi

log "All prerequisite checks passed"


DAILY_JSON="$PARSED_DIR/daily/${DATE}.json"
IP_CSV="$PARSED_DIR/ip_activity/${DATE}.csv"


log "Parsing PCAP for $DATE..."


if [ -f "$DAILY_JSON" ] && [ -f "$IP_CSV" ]; then
    log "  Already parsed skipping"
else
    CASE_STUDY_DAYS="2025-02-13 2025-02-14 2025-02-20 2025-05-15 2025-06-04 2025-06-17 2025-08-06 2025-09-12 2025-10-14 2025-10-30 2025-10-31"

    PARSE_FLAGS=""
    if echo "$CASE_STUDY_DAYS" | grep -qw "$DATE"; then
        PARSE_FLAGS="--detailed"
        log "  Case study day running detailed parse"
    fi

    if python3 "$PYTHON_DIR/daily_parser.py" "$DATE" $PARSE_FLAGS >> "$LOG_FILE" 2>&1; then
        log "  Parse complete"
    else
        log_error "  Parse failed  aborting pipeline for $DATE"
        exit 1
    fi
fi


log "Updating RRD databases..."

if python3 "$PYTHON_DIR/rrd_update.py" "$DAILY_JSON" "$RRD_DIR" >> "$LOG_FILE" 2>&1; then
    log "  RRD updated"
else
    log_error "RRD update failed (continuing)"
fi


log "Running anomaly detection for $DATE..."

if python3 "$PYTHON_DIR/anomaly_detector.py" --date "$DATE" \
    --output "$ANOMALY_FILE" >> "$LOG_FILE" 2>&1; then
    log "  Anomaly detection complete"

    if grep -q "\"date\": \"$DATE\"" "$ANOMALY_FILE" 2>/dev/null; then
        log "ANOMALY DETECTED on $DATE"
    else
        log "  No anomaly"
    fi
else
    log_error "  Anomaly detection failed (continuing)"
fi


log "Generating daily report..."

if python3 "$PYTHON_DIR/report.py" daily "$DAILY_JSON" >> "$LOG_FILE" 2>&1; then
    log "  Report generated"
else
    log_error "  Report generation failed (continuing)"
fi


log "Pipeline complete for $DATE"
log "Log: $LOG_FILE"
