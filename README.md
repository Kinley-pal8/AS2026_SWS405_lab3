# Network Forensics Lab Report - LAB-PC-25 Incident

**Course:** SWS405 Digital Forensics · Unit III
**Scenario:** Suspected compromised host `LAB-PC-25` (`192.168.10.25`) beaconing to an external server.
**Pipeline:** tcpdump → capinfos → TShark → Wireshark → Xplico

> Lab instructions: [Network_Forensics_Lab_Wireshark_tcpdump_tshark_Xplico.md](Network_Forensics_Lab_Wireshark_tcpdump_tshark_Xplico.md)

## Folder layout

```
SWS405_p3/
├── incident.pcap                  # original capture - never modified after Step 2
├── evidence/
│   ├── incident.pcap.sha256_before
│   ├── incident.pcap.sha256_after     # matches before-hash - integrity confirmed
│   └── incident_working_copy.pcap     # all analysis runs against this copy
├── triage_output/                 # tshark text output (Step 4) - run run_triage.sh
├── screenshots/                   # Wireshark + Xplico GUI evidence (Step 5-6)
│   └── README.md                  # checklist of exactly what to capture
└── run_triage.sh                  # runs all Step 4 tshark commands in one shot
```

## Status

| Step | Task | Status |
|------|------|--------|
| 1 | Capture (tcpdump) | ✅ Sample `incident.pcap` used in place of a live capture |
| 2 | Preserve & verify (SHA-256, working copy) | ✅ Done - see below |
| 3 | Scope (capinfos) | ✅ Done - `triage_output/capinfos.txt` |
| 4 | Triage (TShark) | ✅ Done - `triage_output/*.txt` |
| 5 | Deep dive (Wireshark) | ✅ Done - 7 screenshots captured |
| 6 | Artifact reconstruction (Xplico) | ⚠️ Partial - case created, but DNS/Web/Undecoded tabs not screenshotted |
| 7 | Correlate logs | ⚠️ No `dhcp.log` / `dns.log` / `firewall.log` supplied for this exercise - see note below |
| 8 | Timeline & conclusion | ✅ Drafted below from PCAP and Wireshark evidence |

All analysis steps are complete except the deeper Xplico artifact review (Step 6) and the log correlation (Step 7), which were not possible with what was available for this exercise - both are called out explicitly in their sections below rather than glossed over.

---

## Step 2 - Evidence Integrity

```
$ sha256sum incident.pcap
aa8e8987385ab42a3dd91657c151ba088a7d1acd96b34075c94b2a226acaeadb  incident.pcap
```

| When | SHA-256 |
|------|---------|
| Before analysis | `aa8e8987385ab42a3dd91657c151ba088a7d1acd96b34075c94b2a226acaeadb` |
| After analysis | `aa8e8987385ab42a3dd91657c151ba088a7d1acd96b34075c94b2a226acaeadb` |

Hashes match. The original `incident.pcap` was not modified during the investigation.

All analysis was performed against `evidence/incident_working_copy.pcap`; the original `incident.pcap` was not opened by any analysis tool.

## Step 3 - Scope of the Capture

Official output: [`triage_output/capinfos.txt`](triage_output/capinfos.txt)

| Field | Value |
|-------|-------|
| File size | 53 kB (51 kB of data) |
| Packet count | 158 |
| Earliest packet | 2025-05-25 14:00:00.000000 |
| Latest packet | 2025-05-25 14:45:00.010000 |
| Capture duration | 2700.01 seconds (45 minutes, 0.01 seconds) |
| Encapsulation | Ethernet |
| SHA256 | `aa8e8987385ab42a3dd91657c151ba088a7d1acd96b34075c94b2a226acaeadb` (matches evidence table above) |

**Investigation question:** Does the capture window cover the suspected incident? Yes - it spans host boot/DHCP (14:00) through the beaconing and exfiltration window (14:15-14:35) to the post-incident port scan and idle check (14:40-14:45).

## Step 4 - Command-Line Triage

Full command output: [`triage_output/protocol_hierarchy.txt`](triage_output/protocol_hierarchy.txt), [`dns_triage.txt`](triage_output/dns_triage.txt), [`http_triage.txt`](triage_output/http_triage.txt), [`syn_triage.txt`](triage_output/syn_triage.txt), [`host_192.168.10.25_triage.txt`](triage_output/host_192.168.10.25_triage.txt).

### Protocol hierarchy

158 frames total: 2 ARP, 4 DHCP, 6 DNS, 144 TCP (of which only **2** are dissected as real HTTP), 2 ICMP. The bulk of the byte volume (49,212 of 51,173 bytes) is plain TCP - consistent with the large opaque transfer described below.

### DNS queries

| Time | Source | Query | Answer | Assessment |
|------|--------|-------|--------|------------|
| 14:05:00.000 | 192.168.10.25 | `example.com` | 93.184.216.34 | Benign |
| 14:05:05.000 | 192.168.10.25 | `google.com` | 142.250.72.14 | Benign |
| 14:15:20.000 | 192.168.10.25 | `suspicious-example.com` | **203.0.113.50** | **Suspicious** - unrecognized domain, immediately followed by repeating outbound connections |

### HTTP / application traffic

`tshark -Y "http.request"` only matches **one** real HTTP request in the whole capture - the benign browsing session. This matters: the port-8080 traffic is *not* actual HTTP, despite living on a web-adjacent port.

| Time | Source → Dest | Detail |
|------|----------------|--------|
| 14:05:00.340 | 192.168.10.25 → 93.184.216.34:80 | `GET / HTTP/1.1` → `HTTP/1.1 200 OK`, `<html>Welcome, user!</html>` (normal browsing, confirmed via `tshark -z follow,tcp,ascii,0`) |
| 14:15:20 - 14:35:20 (every 5 min) | 192.168.10.25 ⇄ 203.0.113.50:8080 | Five exchanges, fixed sizes (52-byte request / 47-byte response), **payload is opaque binary, not HTTP or plaintext** (confirmed via `tshark -z follow,tcp,ascii,1`) - consistent with an encrypted/obfuscated C2 heartbeat riding a non-standard port |
| **14:32:00.040 - 14:32:00.960** | 192.168.10.25 → **203.0.113.50:4444** | **Real HTTP framing:** `POST /upload HTTP/1.1`, `Host: files.example.com`, `Content-Type: application/octet-stream`, `Content-Length: 40960`, followed by 40,960 bytes of high-entropy binary body; server replies `HTTP/1.1 200 OK`, `Content-Length: 17`, `Upload complete.` (confirmed via `tshark -z follow,tcp,ascii,5`) |

The `Host: files.example.com` header on the port-4444 upload never appears anywhere in the DNS traffic in this capture - either that hostname was resolved before the capture window started, resolved out-of-band, or it's a hardcoded/decoy header. Worth flagging for the DNS log request in the conclusion.

### SYN-only packets (scan / beacon fingerprint)

| Time | Source → Dest | Note |
|------|----------------|------|
| 14:15:20 / 14:20:20 / 14:25:20 / 14:30:20 / 14:35:20 | 192.168.10.25 → 203.0.113.50:8080 | Exactly 300s apart - classic beacon cadence |
| 14:32:00.000 | 192.168.10.25 → 203.0.113.50:4444 | One-off connection for the upload, interleaved mid-beacon |
| 14:40:00.000 - 14:40:00.350 | **192.168.10.30 → 192.168.10.25** on ports 21, 22, 23, 25, 80, 443, 3389, 8080 | Sequential SYNs ~50ms apart from an **internal** host - traffic consistent with port-scanning activity against LAB-PC-25 itself |

## Step 5 - Wireshark Deep Dive

**Protocol Hierarchy** - confirms the same breakdown as `triage_output/protocol_hierarchy.txt`: 158 frames, only 2 dissected as real HTTP.

![Protocol Hierarchy](screenshots/1.png)

**Endpoints** - all 8 addresses in the capture, including the two that matter: `192.168.10.25` (50 kB) and `203.0.113.50` (48 kB).

![Endpoints](screenshots/2.png)

**Conversations, sorted by Bytes A→B** - the port-4444 conversation (`192.168.10.25:55100 ↔ 203.0.113.50:4444`) sits at the very top with 43 kB, clearly the largest transfer in the capture.

![Conversations](screenshots/3.png)

**Display filter `ip.addr == 192.168.10.25`** - isolates every packet touching the suspect host.

![Filter: host](screenshots/4.png)

**Display filter `ip.addr == 192.168.10.25 && dns`** - the three DNS lookups, including the resolution of `suspicious-example.com` to `203.0.113.50`.

![Filter: DNS](screenshots/5.png)

**Display filter `ip.addr == 192.168.10.25 && tcp.flags.syn == 1`** - the five beacon SYNs, the one-off exfil SYN to port 4444, and the port-scan SYNs from `192.168.10.30`, all in one view.

![Filter: SYN](screenshots/6.png)

**Follow → TCP Stream on the port-4444 conversation** - this is the single strongest piece of evidence in the capture. It directly confirms the exfiltration finding from Step 4: `POST /upload HTTP/1.1`, `Host: files.example.com`, `Content-Type: application/octet-stream`, `Content-Length: 40960`, a high-entropy binary body, and the server's `HTTP/1.1 200 OK` / `Upload complete.` reply.

![Follow TCP Stream - port 4444](screenshots/7.png)

Export Objects → HTTP was not screenshotted separately: since the port-8080 beacon traffic is confirmed non-HTTP (opaque binary) and the only two real HTTP frames are the benign `example.com` request/response, Wireshark's HTTP object list would show only that one page - nothing beyond what the Follow TCP Stream screenshot above already documents for the interesting traffic.

### Observation log

| Time | Source | Destination | Protocol | Observation |
|------|--------|-------------|----------|-------------|
| 14:00:00.100 | 0.0.0.0 | 255.255.255.255 | DHCP | LAB-PC-25's MAC (`aa:bb:cc:dd:ee:ff`) requests a lease |
| 14:00:00.150 | 192.168.10.1 | 255.255.255.255 | DHCP | Server replies (192.168.10.25 assigned) |
| 14:05:00.000 | 192.168.10.25 | 8.8.8.8 | DNS | Query for `example.com` - benign |
| 14:15:20.000 | 192.168.10.25 | 8.8.8.8 | DNS | Query for `suspicious-example.com` → 203.0.113.50 |
| 14:15:20 → 14:35:20 | 192.168.10.25 | 203.0.113.50:8080 | TCP | Five beacon connections, exactly 5 minutes apart |
| 14:32:00.040 | 192.168.10.25 | 203.0.113.50:4444 | HTTP | `POST /upload` (40,960-byte binary body, `Host: files.example.com`), then `200 OK` / `Upload complete.` - likely exfiltration |
| 14:40:00.000 | 192.168.10.30 | 192.168.10.25 | TCP | Sequential SYNs to 8 ports - scan fingerprint |
| 14:45:00.000 | 192.168.10.25 | 192.168.10.1 | ICMP | Echo request/reply - routine gateway check |

## Step 6 - Xplico Artifact Reconstruction

The case was created and the working copy uploaded for processing:

![Xplico case created](screenshots/8.png)

**Known limitation of this run:** only the case-creation confirmation was captured. The DNS, Web, and Undecoded/Files tabs were not reviewed or screenshotted, so the cross-checks below are documented as *expected* results based on the TShark/Wireshark findings, not as *confirmed* Xplico output. This gap is called out here rather than presented as done, in keeping with the lab's cross-check discipline: nothing from Xplico should be treated as ground truth without actually looking at it.

Expected cross-checks, still outstanding:
- **DNS tab** should reproduce the same three lookups as `triage_output/dns_triage.txt`, notably `suspicious-example.com → 203.0.113.50`.
- **Web tab** should reconstruct the `93.184.216.34` GET/response pair (real HTTP), and should also pick up the port-4444 `POST /upload` since that stream is genuine HTTP framing, even on a non-standard port. The port-8080 traffic is confirmed **not** real HTTP (opaque binary payload, verified via `tshark -z follow,tcp,ascii`), so Xplico should *not* show it as a web session; if it does, that would be a false positive worth noting.
- **Undecoded/Files tab**: the 40,960-byte binary body from the port-4444 upload is the most likely candidate for extraction; the outcome is unknown until reviewed.

## Step 7 - Correlate With Supporting Logs

No `dhcp.log`, `dns.log`, or `firewall.log` were available for this exercise, so this step could not be performed against real log sources. This is itself noted as an evidence gap rather than skipped silently:

- **DHCP**: the pcap itself shows the lease handshake at 14:00:00 for MAC `aa:bb:cc:dd:ee:ff`, but there is no DHCP server log to independently confirm the IP-to-MAC-to-user mapping.
- **DNS**: no upstream resolver log to confirm `8.8.8.8` is the organization's actual configured resolver, or whether other hosts also queried `suspicious-example.com`.
- **Firewall**: no log to confirm whether the connections to `203.0.113.50:8080/:4444` were explicitly allowed, and by what rule.

If this were a real investigation, these three logs would be requested before finalizing scope (see the "additional evidence" list in the conclusion).

## Step 8 - Timeline & Conclusion

### Consolidated timeline (PCAP only)

| Time | Event |
|------|-------|
| 14:00:00 | LAB-PC-25 (`aa:bb:cc:dd:ee:ff`) obtains DHCP lease for 192.168.10.25 |
| 14:05:00 | Benign DNS + HTTP browsing to `example.com` / `google.com` |
| 14:15:20 | DNS query for `suspicious-example.com` resolves to 203.0.113.50 |
| 14:15:20 - 14:35:20 | Five outbound connections to 203.0.113.50:8080, spaced exactly 5 minutes apart |
| 14:32:00 | Mid-beacon, a separate connection to 203.0.113.50:4444 carries a genuine HTTP `POST /upload` of a 40,960-byte binary body, confirmed with `Upload complete.` |
| 14:40:00 | 192.168.10.30 sends sequential SYNs to 8 ports on 192.168.10.25 |
| 14:45:00 | Routine ICMP echo to the gateway; capture ends |

### Observation (fact only)
192.168.10.25 queried `suspicious-example.com` at 14:15:20, resolving to 203.0.113.50, and then contacted that IP on port 8080 five times at exactly 5-minute intervals between 14:15:20 and 14:35:20. Between the third and fourth beacon, at 14:32:00, the same host sent a 40,960-byte `POST /upload` to 203.0.113.50 on a different port (4444) and received a `200 OK` / `Upload complete.` response. Separately, at 14:40:00, an internal host (192.168.10.30) sent sequential SYN packets to eight ports on 192.168.10.25.

### Interpretation (reasoned, hedged)
The fixed 5-minute interval to 203.0.113.50:8080, carrying fixed-size opaque binary payloads rather than real HTTP, is consistent with automated, scheduled check-in traffic resembling a C2 heartbeat rather than user-driven browsing. The interleaved 40,960-byte `POST /upload` to the same external IP on port 4444 - a port commonly associated with reverse-shell/handler tooling, using genuine HTTP framing to carry a high-entropy binary body to a hostname (`files.example.com`) never seen in this capture's DNS traffic - is consistent with data exfiltration disguised as a file upload. The port scan from 192.168.10.30 against LAB-PC-25 is consistent with either an internal actor probing an already-compromised host, or unrelated network scanning activity; the PCAP alone cannot distinguish these.

### Conclusion (hedged, post-correlation)
The available network evidence supports the conclusion that LAB-PC-25 (192.168.10.25) was communicating periodically with an external system (203.0.113.50) during the investigated window, including at least one transfer of a non-trivial amount of data to that system on a non-standard port. This pattern is consistent with beaconing and possible exfiltration but does not, on its own, prove malware presence, data content, or actor intent. **Endpoint or memory evidence would be required to confirm compromise**; supporting DHCP/DNS/firewall logs were not available in this exercise and should be requested to corroborate the IP-to-device mapping and confirm the firewall's handling of the 203.0.113.50 connections.

### Additional evidence to request
- Endpoint memory/disk forensics on LAB-PC-25 (process listing, autoruns, EDR telemetry) to identify the process responsible for the 8080/4444 connections.
- `dhcp.log`, `dns.log`, `firewall.log` covering 13:55-14:50 on 2025-05-25 to corroborate the PCAP timeline.
- Any proxy/TLS-inspection logs, since real-world beaconing of this kind is often over HTTPS rather than plaintext.
- Netflow/packet capture from other segments to see whether 203.0.113.50 or 192.168.10.30 contacted other internal hosts.

---

## Deliverables Checklist

- [x] SHA-256 hash recorded before analysis
- [x] SHA-256 hash recorded after analysis (unchanged - integrity confirmed)
- [x] `capinfos` output saved (`triage_output/capinfos.txt`)
- [x] TShark triage outputs saved to text files (`triage_output/*.txt`)
- [x] Wireshark screenshots (Protocol Hierarchy, Endpoints, Conversations, Follow TCP Stream)
- [ ] Xplico case export of reconstructed artifacts - case created only; DNS/Web/Files tabs not reviewed
- [x] Correlated timeline table (PCAP-only; DNS/Firewall/DHCP logs unavailable - documented as a gap)
- [x] Final written conclusion using Observation → Interpretation → Conclusion framing
- [x] List of additional evidence to request
