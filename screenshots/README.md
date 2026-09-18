# Screenshots - Evidence Log

GUI evidence for the report (Wireshark and Xplico steps can't be automated
from the CLI). Captured against `evidence/incident_working_copy.pcap`.

## Wireshark (Step 5) - all captured

| File | Content |
|------|---------|
| `1.png` | Statistics → Protocol Hierarchy |
| `2.png` | Statistics → Endpoints (IPv4 tab) |
| `3.png` | Statistics → Conversations, sorted by Bytes A→B - port-4444 conversation on top |
| `4.png` | Display filter `ip.addr == 192.168.10.25` |
| `5.png` | Display filter `ip.addr == 192.168.10.25 && dns` |
| `6.png` | Display filter `ip.addr == 192.168.10.25 && tcp.flags.syn == 1` |
| `7.png` | Follow → TCP Stream on the port-4444 conversation - shows the `POST /upload` exfil in full |

Export Objects → HTTP was not captured separately; see the note in the
main README's Step 5 section for why (the only real HTTP is the benign
`example.com` request already covered elsewhere).

## Xplico (Step 6) - partial

| File | Content |
|------|---------|
| `8.png` | Case creation confirmation (`LABPC25Incident`) |

Still outstanding: DNS tab, Web tab, and Undecoded/Files tab screenshots
after the case finishes processing. The main README documents expected
results for these based on the TShark/Wireshark findings, flagged as
unconfirmed until these are captured.

## Notes

- Crop out unrelated desktop clutter, but keep the whole Wireshark/Xplico
  window chrome (title bar) visible so the tool and filter are obviously
  legible in the image itself.
- If a step produces nothing (e.g., Export Objects finds no files because
  the interesting traffic is HTTP-flagged but not real HTTP), screenshot the
  empty result anyway - a documented negative is still evidence.
