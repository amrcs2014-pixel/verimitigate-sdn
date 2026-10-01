#!/bin/bash
sysctl -q -w net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-arptables=0 net.bridge.bridge-nf-call-ip6tables=0
pgrep dockerd >/dev/null || (nohup dockerd > /var/log/dockerd.log 2>&1 &)
service openvswitch-switch status >/dev/null || service openvswitch-switch start
sleep 3
cd "/mnt/e/network research/p11,12/work/containernet"
rm -f results_real.jsonl
python3 validate.py > validate.log 2>&1
