#!/bin/bash

RRD_DIR="$HOME/ibr-analyst/rrd"
mkdir -p "$RRD_DIR"

#Start timestamp = 2025-01-01 00:00:00 UTC
START=1735689600


#packets.rrd 

if [ -f "$RRD_DIR/packets.rrd" ]; then
    echo "  [skip] packets.rrd already exists"
else
    rrdtool create "$RRD_DIR/packets.rrd" \
        --start $START \
        --step 86400 \
        DS:packets:GAUGE:172800:0:U \
        DS:unique_ips:GAUGE:172800:0:U \
        RRA:AVERAGE:0.5:1:365 \
        RRA:AVERAGE:0.5:7:520 \
        RRA:MAX:0.5:1:365
    echo "  packets.rrd"
fi

#protocols.rrd
if [ -f "$RRD_DIR/protocols.rrd" ]; then
    echo "  [skip] protocols.rrd already exists"
else
    rrdtool create "$RRD_DIR/protocols.rrd" \
        --start $START \
        --step 86400 \
        DS:tcp:GAUGE:172800:0:100 \
        DS:udp:GAUGE:172800:0:100 \
        DS:icmp:GAUGE:172800:0:100 \
        RRA:AVERAGE:0.5:1:365 \
        RRA:AVERAGE:0.5:7:520
    echo "  protocols.rrd"
fi

#ports.rr
if [ -f "$RRD_DIR/ports.rrd" ]; then
    echo "  [skip] ports.rrd already exists"
else
    rrdtool create "$RRD_DIR/ports.rrd" \
        --start $START \
        --step 86400 \
        DS:port1:GAUGE:172800:0:U \
        DS:port2:GAUGE:172800:0:U \
        DS:port3:GAUGE:172800:0:U \
        DS:port4:GAUGE:172800:0:U \
        DS:port5:GAUGE:172800:0:U \
        RRA:AVERAGE:0.5:1:365 \
        RRA:AVERAGE:0.5:7:520
    echo " ports.rrd"
fi

#port_concentration.rrd
if [ -f "$RRD_DIR/port_concentration.rrd" ]; then
    echo "  [skip] port_concentration.rrd already exists"
else
    rrdtool create "$RRD_DIR/port_concentration.rrd" \
        --start $START \
        --step 86400 \
        DS:top5_share:GAUGE:172800:0:100 \
        RRA:AVERAGE:0.5:1:365 \
        RRA:AVERAGE:0.5:7:520 \
        RRA:MAX:0.5:1:365
    echo " port_concentration.rrd"
fi

# churn.rrd
if [ -f "$RRD_DIR/churn.rrd" ]; then
    echo "  [skip] churn.rrd already exists"
else
    rrdtool create "$RRD_DIR/churn.rrd" \
        --start $START \
        --step 86400 \
        DS:churn_pct:GAUGE:172800:0:100 \
        RRA:AVERAGE:0.5:1:365 \
        RRA:AVERAGE:0.5:7:520 \
        RRA:MAX:0.5:1:365
    echo "churn.rrd"
fi
