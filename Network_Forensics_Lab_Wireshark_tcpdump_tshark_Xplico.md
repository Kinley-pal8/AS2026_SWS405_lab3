**SWS405 DIGITAL FORENSICS · UNIT III**

**Practical Lab**

**Network Evidence Analysis**

*Linking tcpdump → capinfos → TShark → Wireshark → Xplico*

*Scenario: Suspected compromised host LAB-PC-25 (IP 192.168.10.25) is
beaconing to an external server.*

**0. Lab Objective**

You will take a single incident down the full forensic pipeline used by
professionals:

CAPTURE → PRESERVE → VERIFY → SCOPE (triage) → EXAMINE (deep dive) →\
RECONSTRUCT ARTIFACTS → CORRELATE LOGS → TIMELINE → CONCLUSION

Each tool below is used for the job it\'s best at --- they are
complementary, not competing:

  -----------------------------------------------------------------------
  **Tool**     **Role**                                 **Analogy**
  ------------ ---------------------------------------- -----------------
  tcpdump      Capture traffic on the wire              The recorder

  capinfos     Instant metadata about a capture         The label on the
                                                        box

  TShark       Fast command-line filtering / field      The sieve
               extraction at scale                      

  Wireshark    Deep, interactive packet-level           The microscope
               investigation                            

  Xplico       Reconstructs application-level artifacts The
               (files, web sessions, emails)            reconstruction
                                                        bench
  -----------------------------------------------------------------------

**1. Prerequisites**

-   A Linux VM/box (or Kali) with tcpdump, tshark, wireshark, xplico
    installed

-   A test network segment or a pre-supplied sample capture
    (incident.pcap)

-   Sudo / root access for live capture

-   Supporting logs if available: firewall.log, dns.log, dhcp.log

> *If you don\'t have live traffic to generate, you can substitute any
> sample .pcap (e.g., from Wireshark\'s sample captures page) for Steps
> 2 onward.*

**2. Step 1 --- Capture the Evidence (tcpdump)**

Why this step: Before you can analyze anything, you need a recording of
the packets. tcpdump is the lightweight, universally-available capture
tool --- ideal for servers or remote systems where a GUI isn\'t
available.

\# Capture all traffic on interface eth0 and save to file\
sudo tcpdump -i eth0 -w incident.pcap

Let it run for a minute or two while generating some traffic (e.g.,
browse a site, run nslookup somedomain.com), then stop with Ctrl+C.

**Explanation of flags**

-   -i eth0 --- capture on interface eth0 (use ip a to find your
    interface name)

-   -w incident.pcap --- write raw packets to file rather than printing
    to screen (preserves full data for later tools)

**Optional targeted captures**

\# Capture only traffic to/from a specific host\
sudo tcpdump -i eth0 -w host_only.pcap host 192.168.10.25\
\
\# Capture only DNS traffic (port 53)\
sudo tcpdump -i eth0 -w dns_only.pcap port 53

> *Forensic note: This filter, applied while capturing, is a capture
> filter --- it determines what gets recorded at all. Anything not
> matching is gone forever. This is different from a display filter
> (Step 4), which only changes what you see in an already-complete
> recording.*

**3. Step 2 --- Preserve & Verify Integrity (sha256sum)**

Why this step: Before any analysis, forensic best practice requires you
to prove the evidence hasn\'t been altered. This is the \"Preserve
Evidence → Verify Hash\" stage of the forensic process.

sha256sum incident.pcap \> incident.pcap.sha256\
cat incident.pcap.sha256

Explanation: This produces a unique fingerprint of the file. Record this
hash in your notes now. At the end of the investigation, re-run the
command --- if the hash matches, you\'ve proven the file was never
modified during your analysis.

Work only on a copy from this point forward; keep the original
untouched.

cp incident.pcap incident_working_copy.pcap

**4. Step 3 --- Scope the Capture (capinfos)**

Why this step: Never dive into individual packets first. Get the \"label
on the box\" --- size, duration, packet count --- so you know what
you\'re dealing with before you start filtering.

capinfos incident_working_copy.pcap

What to read from the output:

  -----------------------------------------------------------------------
  **Field**              **What it tells you**
  ---------------------- ------------------------------------------------
  File size              How much data you\'re dealing with

  Number of packets      Scale of the investigation

  Capture duration       The time window of the incident

  First/last packet      Start and end of activity --- anchors your
  timestamp              timeline
  -----------------------------------------------------------------------

> *Investigation question to answer here: Does the capture window
> actually cover the suspected incident time? If not, you may need more
> evidence.*

**5. Step 4 --- Command-Line Triage (TShark)**

Why this step: With potentially hundreds of thousands of packets, you
don\'t want to scroll manually. TShark lets you rapidly narrow down what
deserves deeper attention --- this is the \"triage\" stage.

**5.1 Get a protocol overview**

tshark -r incident_working_copy.pcap -q -z io,phs

Shows a protocol hierarchy breakdown from the command line --- same
information as Wireshark\'s Statistics → Protocol Hierarchy, but
scriptable.

**5.2 Pull out all DNS queries**

tshark -r incident_working_copy.pcap -Y \"dns\" -T fields \\\
-e frame.time -e ip.src -e ip.dst -e dns.qry.name

Explanation: -Y applies a display filter (only show DNS traffic), -T
fields switches output to structured columns, and each -e picks a
specific field. This turns a packet capture into a clean table you could
pipe into a spreadsheet.

**What to look for:** unusual, randomly-generated, or unfamiliar domain
names (e.g., suspicious-example.com).

**5.3 Pull out HTTP requests**

tshark -r incident_working_copy.pcap -Y \"http.request\" -T fields \\\
-e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri

Reveals exactly what web resources were requested and by whom.

**5.4 Find TCP SYN packets (possible port scanning)**

tshark -r incident_working_copy.pcap -Y \"tcp.flags.syn==1 &&
tcp.flags.ack==0\" \\\
-T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport

**Explanation:** SYN with no ACK = a connection attempt, not a completed
connection. Many of these to sequential ports from one source is the
fingerprint of port scanning --- but remember, this only lets you say
\"traffic consistent with port-scanning activity,\" not proof of a
scan\'s success.

**5.5 Filter to one suspicious host**

tshark -r incident_working_copy.pcap -Y \"ip.addr == 192.168.10.25\" \\\
-T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e frame.len

**Save your triage output --- this becomes evidence in your report:**

tshark -r incident_working_copy.pcap -Y \"dns\" -T fields \\\
-e frame.time -e ip.src -e dns.qry.name \> dns_triage.txt

**6. Step 5 --- Deep-Dive Analysis (Wireshark GUI)**

Why this step: TShark told you what to look at. Now you open the same
file in Wireshark to interactively confirm and understand how the
communication actually happened.

wireshark incident_working_copy.pcap

**6.1 Protocol Hierarchy --- \"What is present?\"**

Statistics → Protocol Hierarchy

Confirms the protocol mix you saw in TShark\'s io,phs output, now with
percentages and byte counts, tree-structured by layer.

**6.2 Endpoints --- \"Who is communicating?\"**

Statistics → Endpoints

Lists every IP address that appears. Look for external IPs your
organization has no business talking to.

**6.3 Conversations --- \"Who is talking to whom, and how much?\"**

Statistics → Conversations

Sort by Bytes to spot the largest data transfers --- a strong indicator
of exfiltration. Sort by Duration to spot long-lived sessions typical of
a reverse shell or C2 channel.

**6.4 Apply display filters to isolate the suspicious host**

In the filter bar at the top:

ip.addr == 192.168.10.25

Then narrow further:

ip.addr == 192.168.10.25 && dns\
ip.addr == 192.168.10.25 && tcp.flags.syn == 1

**Explanation:** Unlike tcpdump\'s capture filter, this is a **display
filter** --- the full capture is still on disk; you\'re just changing
the view to focus your eyes.

**6.5 Follow the TCP Stream**

**Right-click a packet in the suspicious conversation → Follow → TCP
Stream.**

Explanation: This reconstructs the entire back-and-forth conversation
into readable text (for unencrypted protocols like HTTP). This is where
you might see an actual GET /upload request, a login attempt, or file
transfer content.

**6.6 Export any recoverable objects**

File → Export Objects → HTTP (or SMB/DICOM depending on protocol
present).

This pulls out any file that was transferred in the clear --- direct
file-level evidence.

**Record your findings in a table as you go:**

  --------------------------------------------------------------------------------------
  **Time**   **Source**      **Destination**   **Protocol**   **Observation**
  ---------- --------------- ----------------- -------------- --------------------------
  10:15:20   192.168.10.25   8.8.8.8           DNS            Query for
                                                              suspicious-example.com

  10:15:22   192.168.10.25   185.X.X.X         TCP/443        TLS session established
  --------------------------------------------------------------------------------------

**7. Step 6 --- Reconstruct Application Artifacts (Xplico)**

Why this step: Wireshark shows you packets; Xplico answers a different
question: \"What usable, human-readable artifact can be rebuilt from
this traffic?\" --- web pages viewed, files transferred, emails sent,
VoIP calls.

**7.1 Start Xplico and create a case**

sudo /etc/init.d/xplico start

Log into the Xplico web interface (typically http://localhost:9876),
then:

1.  New Case → name it (e.g., LAB-PC-25_Incident)

2.  New Session inside the case

3.  Upload / Import your incident_working_copy.pcap

**7.2 Let Xplico process the capture**

Xplico runs the pipeline automatically:

PCAP → Protocol Decoding → Session Reconstruction → Artifacts → Hashing

**7.3 Review reconstructed artifacts**

In the case dashboard, check each tab:

-   **Web** --- reconstructed pages/URLs visited (parallels the HTTP
    host/URI you pulled with TShark in 5.3)

-   **Site (HTTP)** --- actual rendered content where possible

-   **Undecoded/Files** --- any extracted files, viewable and hashable

-   **DNS** --- resolved domain lookups (cross-check against your
    dns_triage.txt)

**7.4 Know the limits**

Xplico cannot reconstruct:

-   Encrypted payloads (HTTPS/TLS) without decryption keys

-   Protocols it doesn\'t support

-   Data lost to packet loss or a corrupted capture

-   Traffic that never passed the capture point

> *Cross-check discipline: Never treat an Xplico artifact as ground
> truth on its own --- always confirm it against what you already saw in
> Wireshark/TShark for the same timestamp and IP.*

**8. Step 7 --- Correlate With Supporting Logs**

Why this step: \"One network event rarely tells the complete story.\"
PCAP evidence alone proves communication happened --- it doesn\'t prove
who used the device or why the connection was allowed.

If you have dhcp.log, dns.log, and firewall.log available, walk the same
incident through each source:

\# Example: search DHCP log for the IP-to-device mapping\
grep \"192.168.10.25\" dhcp.log\
\
\# Example: search firewall log for the allow/deny decision\
grep \"185.X.X.X\" firewall.log

Build a combined table:

  -----------------------------------------------------------------------
  **Time**     **Source**        **Event**
  ------------ ----------------- ----------------------------------------
  10:14:55     DHCP              IP 192.168.10.25 assigned to MAC
                                 AA:BB:CC:DD:EE:FF

  10:15:20     DNS               Query: suspicious-example.com

  10:15:22     Firewall          Connection to 185.X.X.X:443 --- ALLOWED

  10:15:22     PCAP              TCP handshake completes, TLS negotiated

  10:20:22     PCAP/Firewall     Same destination contacted again ---
                                 repeats every 5 min
  -----------------------------------------------------------------------

> *Time synchronization check: Before trusting the sequence, confirm all
> sources use the same clock reference (UTC vs local time, NTP sync
> status). A few seconds of drift across DHCP/DNS/Firewall/PCAP
> timestamps is normal and doesn\'t break the correlation --- but large
> unexplained gaps should be flagged.*

**9. Step 8 --- Build the Timeline and Write the Conclusion**

Lay out every correlated event in strict chronological order (this is
your forensic timeline), then apply the Observation → Interpretation →
Conclusion discipline:

**1. Observation (fact only):**

> *\"192.168.10.25 contacted 185.X.X.X every 5 minutes over a 15-minute
> window, preceded by a DNS query to suspicious-example.com.\"*

**2. Interpretation (reasoned, hedged):**

> *\"This pattern is consistent with periodic automated communication,
> resembling beaconing behavior.\"*

**3. Conclusion (only after correlation, still hedged appropriately):**

> *\"The available network evidence supports the conclusion that the
> workstation was communicating periodically with the identified
> external system during the investigated period. Endpoint or memory
> evidence would be required to confirm the presence of malware.\"*

**Never write:** \"The machine is definitely infected\" --- network
evidence alone cannot prove that.

**10. Lab Deliverables Checklist**

> **☐** SHA-256 hash recorded before and after analysis (unchanged)
>
> **☐** capinfos output (capture scope)
>
> **☐** TShark triage outputs (DNS, HTTP, SYN scan check) saved to text
> files
>
> **☐** Wireshark screenshots: Protocol Hierarchy, Endpoints,
> Conversations, Follow TCP Stream
>
> **☐** Xplico case export of any reconstructed artifacts
>
> **☐** Correlated timeline table (PCAP + DNS + Firewall + DHCP)
>
> **☐** Final written conclusion using Observation → Interpretation →
> Conclusion framing
>
> **☐** List of any additional evidence you would request (e.g.,
> endpoint memory dump, EDR logs)

**11. Quick Reference --- All Commands Used**

\# 1. Capture\
sudo tcpdump -i eth0 -w incident.pcap\
\
\# 2. Preserve/verify\
sha256sum incident.pcap\
cp incident.pcap incident_working_copy.pcap\
\
\# 3. Scope\
capinfos incident_working_copy.pcap\
\
\# 4. Triage\
tshark -r incident_working_copy.pcap -q -z io,phs\
tshark -r incident_working_copy.pcap -Y \"dns\" -T fields -e frame.time
-e ip.src -e dns.qry.name\
tshark -r incident_working_copy.pcap -Y \"http.request\" -T fields -e
frame.time -e ip.src -e http.host -e http.request.uri\
tshark -r incident_working_copy.pcap -Y \"tcp.flags.syn==1 &&
tcp.flags.ack==0\" -T fields -e frame.time -e ip.src -e tcp.dstport\
\
\# 5. Deep dive\
wireshark incident_working_copy.pcap\
\# Statistics -\> Protocol Hierarchy / Endpoints / Conversations\
\# Filter bar: ip.addr == 192.168.10.25\
\# Right-click packet -\> Follow -\> TCP Stream\
\# File -\> Export Objects -\> HTTP\
\
\# 6. Artifact reconstruction\
sudo /etc/init.d/xplico start\
\# Web UI: New Case -\> New Session -\> Upload
incident_working_copy.pcap\
\# -\> review Web/DNS/Files tabs\
\
\# 7. Correlate logs\
grep \"192.168.10.25\" dhcp.log\
grep \"185.X.X.X\" firewall.log
