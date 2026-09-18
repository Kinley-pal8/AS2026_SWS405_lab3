#!/bin/bash
# Runs the Step 3-4 command-line triage (capinfos + tshark) from the lab guide
# against the preserved working copy, saving every output to triage_output/
# for inclusion in the final report.
set -euo pipefail

cd "$(dirname "$0")"
PCAP="evidence/incident_working_copy.pcap"
OUT="triage_output"
mkdir -p "$OUT"

echo "== capinfos =="
capinfos "$PCAP" | tee "$OUT/capinfos.txt"

echo "== Protocol hierarchy =="
tshark -r "$PCAP" -q -z io,phs | tee "$OUT/protocol_hierarchy.txt"

echo "== DNS queries =="
tshark -r "$PCAP" -Y "dns" -T fields \
  -e frame.time -e ip.src -e ip.dst -e dns.qry.name \
  | tee "$OUT/dns_triage.txt"

echo "== HTTP requests =="
tshark -r "$PCAP" -Y "http.request" -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
  | tee "$OUT/http_triage.txt"

echo "== SYN scan check =="
tshark -r "$PCAP" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields \
  -e frame.time -e ip.src -e ip.dst -e tcp.dstport \
  | tee "$OUT/syn_triage.txt"

echo "== Suspicious host filter (192.168.10.25) =="
tshark -r "$PCAP" -Y "ip.addr == 192.168.10.25" -T fields \
  -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e frame.len \
  | tee "$OUT/host_192.168.10.25_triage.txt"

echo ""
echo "All triage outputs saved under $OUT/"
