# Screenshots — Capture Checklist

This folder holds the GUI evidence for the report (Wireshark and Xplico steps
can't be automated from the CLI, so these must be captured by hand while you
work through Steps 5–6 of the lab).

Use the working copy for everything: `evidence/incident_working_copy.pcap`.
Save each screenshot with the **exact filename** below (PNG) so the README's
image links resolve automatically.

## Wireshark (Step 5)

| # | Filename | When to take it | What must be visible |
|---|----------|------------------|-----------------------|
| 1 | `01_protocol_hierarchy.png` | After opening the pcap → **Statistics → Protocol Hierarchy** | Full protocol tree with percent/byte columns |
| 2 | `02_endpoints.png` | **Statistics → Endpoints** → IPv4 tab | All endpoint IPs, including `203.0.113.50` and `192.168.10.30` |
| 3 | `03_conversations.png` | **Statistics → Conversations** → TCP tab, sorted by **Bytes** (click the column header) | The port-4444 conversation with 192.168.10.25 sorted near the top |
| 4 | `04_display_filter_host.png` | Type `ip.addr == 192.168.10.25` in the filter bar and press Enter | Filter bar + resulting packet list |
| 5 | `05_display_filter_dns.png` | Filter `ip.addr == 192.168.10.25 && dns` | The three DNS query/response pairs, including `suspicious-example.com` |
| 6 | `06_display_filter_syn.png` | Filter `ip.addr == 192.168.10.25 && tcp.flags.syn == 1` | The beaconing SYNs to `203.0.113.50:8080` and the exfil SYN to `:4444` |
| 7 | `07_follow_tcp_stream_4444.png` | Right-click any packet in the `203.0.113.50:4444` conversation → **Follow → TCP Stream** | The `POST /upload HTTP/1.1` request and the `200 OK` reply, with the stream colorized (red=client, blue=server) |
| 8 | `08_export_objects_http.png` | **File → Export Objects → HTTP** | The object list dialog (even if nothing is exportable from the raw payload, capture the dialog to document that this step was performed) |

## Xplico (Step 6)

| # | Filename | When to take it | What must be visible |
|---|----------|------------------|-----------------------|
| 9  | `09_xplico_new_case.png` | After creating the case (`LAB-PC-25_Incident`) and session, before/during upload | Case name and session name |
| 10 | `10_xplico_dns_tab.png` | Case dashboard → **DNS** tab, after processing finishes | Resolved lookups, including `suspicious-example.com → 203.0.113.50` |
| 11 | `11_xplico_web_tab.png` | Case dashboard → **Web** tab | Reconstructed HTTP hits to `93.184.216.34` (and the 8080/4444 traffic if Xplico attempts to decode it) |
| 12 | `12_xplico_undecoded_files.png` | Case dashboard → **Undecoded / Files** tab | Any extracted objects, or the empty state (document either outcome) |

## Naming convention

`NN_short-description.png` — zero-padded number keeps screenshots in capture
order in every file browser; the description makes each one self-explanatory
without opening it. Keep everything flat in this folder (no subfolders) so
the README's relative links (`screenshots/01_....png`) keep working.

## Notes

- Crop out unrelated desktop clutter, but keep the whole Wireshark/Xplico
  window chrome (title bar) visible so the tool and filter are obviously
  legible in the image itself.
- If a step produces nothing (e.g., Export Objects finds no files because
  the interesting traffic is HTTP-flagged but not real HTTP), screenshot the
  empty result anyway — a documented negative is still evidence.
