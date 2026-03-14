# Internet Connection Interruption Monitor - README.md

> **Purpose:** Continuous, automated monitoring of internet connectivity
> with timestamped evidence collection, designed to produce legally usable PDF reports
> documenting service quality failures by an Internet Service Provider (ISP).
> Created purely out of spite to my current ISP with which I am battling for two years now
> yes 1und1, you know I am talking about you, let's see how your support likes that.

---

## Table of Contents

1. [Overview](#overview)
2. [How It Works - Technical Detail](#how-it-works--technical-detail)
3. [What Gets Measured](#what-gets-measured)
4. [Metadata Collected](#metadata-collected)
5. [JSONL Event Log](#jsonl-event-log)
6. [PDF Report Contents](#pdf-report-contents)
7. [SHA-256 Integrity Hash](#sha-256-integrity-hash)
8. [Automatic Report Updates](#automatic-report-updates)
9. [Security Measures](#security-measures)
10. [Why This Evidence Is Reliable](#why-this-evidence-is-reliable)
11. [Installation & Usage](#installation--usage)
12. [Configuration Options](#configuration-options)
13. [File Structure](#file-structure)
14. [Glossary](#glossary)

---

## Overview

**The README is deliberately verbose for legal/evidentiary purposes.**
This script runs on a local computer connected to the customer's internet
service. It continuously tests whether the internet connection is functional
by attempting to reach **three independent, well-known external servers**
simultaneously. Every time the connection drops or recovers, the event
is recorded with a precise timestamp. In addition to connectivity, the tool
measures **TCP handshake latency** and **DNS resolution** on every check cycle.

All events are written in real-time to a **JSONL (JSON Lines) log file**
for tamper-evident, machine-readable record keeping. When monitoring
is stopped (or at any time via the "Save Report Now" button,
or automatically at midnight), a formatted PDF report is generated containing:

- Exact times of every disconnection and reconnection
- Duration of each outage
- **Outage cause** (ISP vs Router/LAN, determined by gateway reachability)
- Total accumulated downtime and uptime percentage
- TCP latency statistics (average, min, max, P50, P95)
- DNS resolution success/failure tracking
- Full network and system metadata (public IP, ISP name, local IP, OS, etc.)
- Optional **SNMP router monitoring** (interface errors, discards, uptime)
- **TLS certificate pinning** for external API requests
- SHA-256 integrity hash of the report data

The report serves as **objective, machine-generated evidence** of the quality
of service actually delivered versus what was contractually promised.

---

## How It Works - Technical Detail

### Multi-Target Connectivity Test

The script uses **TCP connection attempts** to test internet reachability
against **three independent targets simultaneously**:

| Target       | Provider     | IP         | Port | Published Uptime |
|--------------|--------------|------------|------|------------------|
| Cloudflare   | Cloudflare   | `1.1.1.1`  | 53   | 99.999%          |
| Google DNS   | Google       | `8.8.8.8`  | 53   | 99.999%          |
| Quad9        | Quad9/IBM    | `9.9.9.9`  | 53   | 99.999%          |

**Why three targets?**

- If a single target were used, a temporary issue with that specific server
  (however unlikely) could be argued as a false positive.

- With three independent providers on three different networks, the probability
  of all three being simultaneously unreachable due to anything other than
  a local/ISP network failure is astronomically low.

- The connection is considered **DOWN** only when **ALL three targets**
  are unreachable. If even one responds, the connection is considered **UP**.

- This makes false positives essentially impossible and the evidence
  irrefutable.

**Why TCP to port 53?**

- ICMP ping is sometimes deprioritized or blocked by routers; TCP on port 53 is
  universally allowed and treated as normal traffic.

- The 3-second timeout is deliberately lenient. A working connection completes
  the handshake in under 50ms. If 3 seconds pass without success, the
  connection is genuinely non-functional.

### Latency Measurement

Every TCP connection attempt that succeeds also measures the **handshake
latency** - the time from initiating the connection to completing the TCP
three-way handshake. This is recorded in milliseconds
and aggregated into statistics:

- **Average latency** across the entire monitoring session

- **Minimum / Maximum** observed latency

- **P50 (median)** - half of all measurements are faster than this

- **P95** - 95% of measurements are faster than this (worst-case performance)

High latency (even without full disconnections) can constitute degraded service
and may be relevant to QoS complaints.

### DNS Resolution Test

Every check cycle also tests **DNS resolution** by sending a **raw UDP DNS
query** directly to 1.1.1.1:53, requesting the A record for `google.com`.
This is critically different from using the operating system's built-in
name resolution (`gethostbyname`), which consults a local DNS cache. Cached
results can return "OK" even when the connection is completely down
(e.g. during a PPPoE disconnect), producing false positives.

By constructing and sending the DNS packet manually over UDP, the test:

- **Bypasses the OS DNS cache entirely** - every check sends a real packet
  over the network

- **Fails immediately when the connection is down** - no cached result can
  mask an outage

- **Measures true DNS round-trip latency** - the time from sending the UDP
  query to receiving the response

- **Requires no external libraries** - the DNS packet is built from raw bytes

This catches a specific class of ISP problems:

- **DNS server failures**: The ISP's DNS infrastructure may go down even when
  raw IP connectivity works.

- **DNS hijacking or corruption**: Some ISPs interfere with DNS resolution.

- **Partial outages**: TCP to a known IP may work, but name resolution fails,
  making the internet effectively unusable for normal browsing.

- **PPPoE/connection-level drops**: The raw UDP query will time out, whereas
  the OS cache would still return stale results.

DNS failures that occur **while TCP connectivity is working** are logged
separately as they indicate ISP DNS infrastructure problems specifically.

### Gateway Reachability Check

On every check cycle the monitor also tests whether the **default gateway**
(router) is reachable. The gateway IP is auto-detected from the OS routing
table at startup, or can be set manually in `config.py`.

When an outage occurs the gateway state determines the **cause**:

| Gateway reachable? | Meaning                                                   |
|--------------------|-----------------------------------------------------------|
| **Yes**            | Router is up - the problem is with the **ISP** uplink     |
| **No**             | Router itself is down or unreachable - **Router/LAN** issue |
| **Unknown**        | Gateway detection disabled or IP not configured           |

This distinction is critical for ISP complaints: if the router is reachable
but the internet is not, the fault lies with the ISP, not the customer's
equipment.

### Optional SNMP Router Monitoring

For routers that support **SNMPv2c**, the monitor can poll interface
counters to detect hardware-level problems:

- **ifInErrors / ifOutErrors** - CRC errors, framing errors, etc.
- **ifInDiscards / ifOutDiscards** - packets dropped due to buffer overflows
- **ifOperStatus** - whether the WAN interface is up/down
- **sysUpTime** - router uptime (detects reboots)

SNMP packets are built from raw bytes using only stdlib (`socket` + `struct`),
matching the project's no-external-dependencies philosophy. If the router
does not respond (e.g. SNMP is disabled, as on AVM FRITZ!Box devices),
SNMP is silently disabled at startup.

To enable: set `SNMP_ENABLED = True` in `config.py` and adjust
`SNMP_HOST` / `SNMP_COMMUNITY` as needed.

### Detection Logic

```
Every 5 seconds:

  1. Attempt TCP connection to 1.1.1.1:53, 8.8.8.8:53, 9.9.9.9:53 concurrently (3s timeout)
  2. Record latency for each successful connection
  3. Send raw UDP DNS query for google.com to 1.1.1.1:53 (bypasses OS cache, 3s timeout)
  4. Check gateway (router) reachability via TCP to common ports (80, 443, 53)
  5. If previously CONNECTED and ALL targets FAIL → record DISCONNECT event (with cause)
  6. If previously DISCONNECTED and ANY target SUCCEEDS → record RECONNECT event
  7. If DNS fails but TCP succeeds → record DNS_FAILURE event
  8. Write event to JSONL log file
  9. Every 60s: poll SNMP counters from router (if enabled)
```

This state-machine approach means:

- Only **transitions** are logged as events (not every single check)

- Periodic health checks are logged every 60 seconds for continuity of evidence

- The exact **second** of disconnection and reconnection is captured (±5s precision)

- Continuous outages are tracked as a single event with a measured duration

- DNS failures are tracked independently from connectivity failures

### Threading Model & Concurrency

- **Main thread**: Runs the graphical dashboard (Tkinter),
  ensuring the UI remains responsive at all times.

- **Background thread**: Performs connectivity checks, latency measurements,
  and DNS tests every 5 seconds. This separation ensures that network timeouts
  never freeze the user interface.

- **Concurrent target checks**: All three TCP targets are checked in parallel
  using a thread pool, so a single unresponsive target does not delay the
  others. Worst-case check time is 3 seconds (the timeout), not 9 seconds.

- **Thread-safe shared state**: All data shared between the background
  monitoring thread and the GUI thread is protected by a mutex lock,
  ensuring consistent reads even during rapid state transitions.

### Lifecycle

1. **Startup**: Collects system and network metadata (public IP, ISP, hostname,
   OS, local IP). Initializes the JSONL log file with session metadata.

2. **Monitoring**: Runs indefinitely, checking all targets + DNS every 5 seconds.
   The GUI updates live statistics every 1 second.

3. **Automatic report updates**: At midnight each day, the PDF report is
   updated with the latest data, without interrupting monitoring.

4. **Shutdown** (any of these triggers):
   - User closes the GUI window
   - User presses `Ctrl+C` in the terminal
   - System sends `SIGTERM`

   Shutdown is handled gracefully: signals set an internal stop flag and
   schedule the GUI close via Tkinter's event loop, avoiding deadlocks
   or file corruption from I/O inside signal handlers.

5. **Final report**: On shutdown, any ongoing outage is closed, the session end
   is logged, and a final PDF is generated.

---

## What Gets Measured

| Metric                     | Description                                                    |
|----------------------------|----------------------------------------------------------------|
| **Disconnect time**        | Exact timestamp when all targets became unreachable            |
| **Reconnect time**         | Exact timestamp when any target became reachable again         |
| **Outage duration**        | Calculated difference (reconnect − disconnect)                 |
| **Total downtime**         | Sum of all individual outage durations                         |
| **Total uptime**           | Monitoring duration minus total downtime                       |
| **Uptime percentage**      | `(uptime / monitoring_duration) × 100`                         |
| **Number of outages**      | Count of distinct disconnect→reconnect events                  |
| **TCP latency (per target)** | Handshake time in ms for each successful connection          |
| **Latency statistics**     | Average, min, max, P50, P95 across all samples                |
| **DNS resolution success** | Whether `google.com` resolved successfully                     |
| **DNS latency**            | Time to resolve the domain name in ms                          |
| **DNS failures**           | Count and timestamps of DNS failures while TCP worked          |
| **Per-target results**     | Which specific targets were reachable/unreachable at each event|
| **Local IP at disconnect** | The machine's LAN IP when the outage began                     |
| **Public IP at reconnect** | The public-facing IP after service was restored                |
| **ISP at reconnect**       | ISP organization name after reconnection                       |
| **Gateway reachable**      | Whether the router was reachable when the outage started       |
| **Outage cause**           | ISP (gateway up) or Router/LAN (gateway down)                  |
| **SNMP counters**          | Interface errors, discards, status, uptime (if SNMP enabled)   |

---

## Metadata Collected

At startup, the following metadata is gathered and embedded in every report
and the JSONL log file:

| Field               | Source                | Purpose                                              |
|---------------------|-----------------------|------------------------------------------------------|
| **Public IP**       | ipinfo.io API         | Proves which ISP connection was being used           |
| **ISP / Org**       | ipinfo.io API         | Identifies the Internet Service Provider by name     |
| **Location**        | ipinfo.io API         | City, region, country - confirms geographic context  |
| **Local IP**        | OS network stack      | Identifies the monitoring machine on the LAN         |
| **Hostname**        | OS hostname           | Identifies the specific computer running the test    |
| **Operating System**| `platform` module     | Documents the test environment                       |
| **Targets**         | Configuration         | Lists all three test endpoints                       |
| **DNS test domain** | Configuration         | Shows which domain is used for DNS testing           |
| **Check interval**  | Configuration         | Documents measurement frequency                      |
| **Ping timeout**    | Configuration         | Documents the failure threshold                      |
| **Gateway IP**      | OS routing table      | Default gateway (router) for cause determination     |

This metadata establishes the **chain of evidence**: which computer, on which
network, connected to which ISP, was measuring connectivity to which targets,
and how often.

---

## JSONL Event Log

Alongside PDF reports, the monitor writes a **real-time JSONL (JSON Lines)**
log file. Each line is a self-contained JSON object with a `type` field.

**Filename:** `connection_log.jsonl`

There is a single JSONL file that persists across restarts. If the monitor
is restarted, it appends to the existing file and **resumes accumulated
state** (events, downtime, latency/DNS samples) so no data is lost.

### Event Types

| Type             | When Written                          | Contains                                    |
|------------------|---------------------------------------|----------------------------------------------|
| `session_start`  | Monitor startup                       | Full metadata, timestamp                     |
| `check`          | Every 60 seconds                      | All target results, DNS, gateway, SNMP       |
| `disconnect`     | Connection lost                       | Timestamp, local IP, gateway state, cause    |
| `reconnect`      | Connection restored                   | Timestamp, duration, new IP/ISP, cause       |
| `dns_failure`    | DNS fails but TCP works               | Timestamp, DNS result, which targets were OK |
| `session_end`    | Monitor shutdown                      | Timestamp, total downtime, event counts      |

### Why JSONL?

- **Append-only**: Each event is written immediately, so data survives crashes.

- **Machine-readable**: Can be parsed, queried, and verified programmatically.

- **Tamper-evident**: Modifying entries in the middle of the file would
  be detectable by inconsistent timestamps or gaps.

- **Complements the PDF**: The PDF is human-readable; the JSONL
  is the raw data source that can be independently verified.

---

## PDF Report Contents

Each generated PDF contains the following sections:

### 1. Title

"Internet Connection Report"

### 2. Summary Box

- Monitoring start and end timestamps
- Total monitoring duration
- Total accumulated downtime
- Uptime percentage
- Number of outages recorded

### 3. Connection Metadata Box

- All metadata fields (public IP, ISP, location, local IP, hostname, OS,
  all three targets, DNS test domain, check interval, timeout)

### 4. Latency Statistics Box

- Total number of latency samples collected
- Average TCP handshake latency
- Minimum / Maximum latency
- P50 (median) / P95 (95th percentile) latency

### 5. DNS Resolution Statistics Box

- Test domain used
- Number of successful DNS lookups
- Average DNS resolution latency
- Number of DNS failures (while TCP was working)

### 6. Router Diagnostics Box (SNMP, when enabled)

- Router host and interface index
- SNMP agent reachability
- System uptime (formatted from timeticks)
- WAN interface description and operational status
- Traffic in/out (human-readable byte formatting)
- Error and discard counters (in/out)

All SNMP string values are sanitized before rendering to guard against
malicious or malformed SNMP responses.

### 7. Outage Events Table

- **#** - Sequential outage number

- **Disconn.** - Time of connection loss (HH:MM:SS)

- **Reconn.** - Time of restoration (HH:MM:SS, or "-" if still down)

- **DNS** - DNS resolution status at disconnect/reconnect

- **Duration** - Length of the outage

- **Cause** - "ISP" (gateway up), "Router" (gateway down), or "-"

- **IP / ISP / Location** - Shown only when changed after reconnection

### 8. Footer

- Report generation timestamp
- All target hosts listed
- Check interval
- **SHA-256 hash** of the report data

---

## SHA-256 Integrity Hash

Every PDF report includes a **SHA-256 cryptographic hash** in its footer. This
hash is computed over the canonical JSON representation of the report data:

- Start and end timestamps
- Total downtime
- All outage events (disconnect/reconnect times and durations)
- Full metadata
- Latency and DNS failure counts

**Purpose:**

- Proves the report has not been altered after generation
- The same data will always produce the same hash
- Anyone with the raw JSONL log can independently recompute the hash and
  verify it matches the PDF footer
- Provides a verifiable fingerprint for legal proceedings

---

## Automatic Report Updates

The monitor produces a single PDF report, `internet_report.pdf`. Every
save operation (manual snapshot, midnight auto-save, or final report on
shutdown) **overwrites** this file with the latest accumulated data.

- Named `internet_report.pdf` (fixed name, no date suffix)
- Contains all data accumulated since monitoring started
- Generated without interrupting the monitoring process
- Automatically updated at midnight, on manual save, and on shutdown
- Protects against data loss if the script is unexpectedly terminated

The same applies to the **JSONL log file** (`connection_log.jsonl`) -
a single file, appended across restarts. On startup the monitor parses
the existing log and restores all prior events, downtime, and
latency/DNS samples so the next PDF report includes the full history.

---

## Security Measures

Since this tool produces evidence intended for ISP complaints and potentially
legal proceedings, data integrity and security are taken seriously. The
following measures are implemented:

### File Permissions

- JSONL log files are created with **owner-only permissions** (`0o600`)
- PDF reports have `os.chmod(filename, 0o600)` applied after generation
- Output files contain sensitive metadata (IP addresses, ISP, location)

### TLS Certificate Pinning (TOFU)

- Connections to `ipinfo.io` use **SPKI (Subject Public Key Info) pinning**
- On first connection, the SHA-256 hash of the server's public key is learned
  and saved to `.ipinfo_cert_pin`
- Subsequent connections verify the server's key matches the saved pin
- A mismatch (potential MITM) causes the connection to be rejected
- SPKI pinning survives normal certificate renewals (same key = same pin)
- To re-learn after a legitimate key rotation, delete `.ipinfo_cert_pin`

### Cryptographic Randomness

- DNS transaction IDs use `secrets.randbelow()` instead of `random.randint()`
- SNMP request IDs use `secrets.randbelow()` for unpredictable values
- Prevents prediction-based spoofing of DNS/SNMP responses

### Response Verification

- DNS responses are verified against the original transaction ID
- SNMP responses are verified against the original request ID
- Spoofed network responses with mismatched IDs are rejected

### Input Validation

- `ipinfo.io` responses are validated (IP format regex, string length caps)
- Gateway detection subprocess output is validated as a proper IP address
- SNMP string values are sanitized (control chars stripped, length-capped)
  before PDF rendering
- Log filenames are restricted to the current directory via `os.path.basename()`

### Rate Limiting

- `ipinfo.io` results are cached for 60 seconds to prevent rapid-fire
  requests during connection flapping

### SNMP Community String

- Loaded from the `SNMP_COMMUNITY` environment variable (not hardcoded)
- Falls back to `"public"` if unset
- Note: SNMPv2c transmits the community string in cleartext (protocol limitation)

### Memory Safety

- All sample collections use bounded `deque` structures (max 50,000 entries)
- Event and DNS failure lists are also bounded to prevent memory exhaustion
  during long-running sessions

---

## Why This Evidence Is Reliable

1. **Three independent targets**: Cloudflare (1.1.1.1), Google (8.8.8.8), and
   Quad9 (9.9.9.9) are operated by different organizations on different
   networks. All three failing simultaneously proves the problem is on the
   ISP's side, not the target's.

2. **Conservative thresholds**: A 3-second timeout means only genuine failures
   are recorded. Brief latency spikes do not trigger false disconnections.

3. **Machine-generated UTC timestamps**: All times are recorded internally in
   UTC via `datetime.now(timezone.utc)`, making them immune to DST transitions
   or timezone changes. Displayed times are converted to local time for
   readability. There is no manual input or subjective assessment.

4. **Continuous, unattended operation**: The script runs autonomously. It cannot
   "miss" outages or selectively report them.

5. **Real-time logging**: Events are written to the JSONL log immediately as
   they occur, not retroactively. The log file survives crashes.

6. **DNS testing**: Captures ISP DNS failures separately from connectivity
   failures, proving specific infrastructure problems.

7. **Latency evidence**: Even when the connection doesn't fully drop, high
   latency is documented with statistical rigour (averages, percentiles).

8. **Metadata proves context**: The ISP name, public IP, and location are
   fetched from an independent third-party API (ipinfo.io), not self-reported.

9. **SHA-256 integrity hash**: Each report carries a cryptographic fingerprint
   that can be independently verified against the raw log data.

10. **Tamper-evident logging**: The append-only JSONL format with sequential
    timestamps makes modifications detectable.

11. **Bounded memory usage**: All sample collections, events, and DNS failures
    are stored in bounded structures (up to 50,000 entries), allowing the
    monitor to run for weeks without unbounded memory growth.

12. **Open source**: The measurement methodology is fully transparent and can be
    independently reviewed or audited.

13. **Gateway-based cause determination**: When the router is reachable but the
    internet is not, the outage is attributed to the ISP. When the router
    itself is unreachable, the cause is local. This distinction is logged
    and displayed in the PDF report.

14. **No external dependencies for networking**: All network checks (TCP, DNS,
    SNMP, gateway) use only Python stdlib. The only external dependency is
    `fpdf2` for PDF generation.

15. **Security hardening**: TLS certificate pinning for external API requests,
    cryptographic randomness for network transaction IDs, response
    verification for DNS/SNMP, owner-only file permissions, and input
    validation on all external data sources. See
    [Security Measures](#security-measures) for details.

---

## Installation & Usage

### Prerequisites

- Python 3.13 or later
- `tkinter` (included with most Python installations)
- `fpdf2` library
- [`uv`](https://docs.astral.sh/uv/) (recommended package/environment manager)

### Setup

```bash
# Create and activate a virtual environment
uv venv venv
source venv/bin/activate

# Install dependencies
uv add -r requirements.txt
```

### User Configuration (`user.py`)

Before running, create a `user.py` file with your personal and contract
details. These are embedded in the generated PDF report to identify the
complainant and the associated service contract.

> **Note:** `user.py` is listed in `.gitignore` and will **not** be
> uploaded to GitHub. You must create it manually.

```python
"""User-specific details for PDF reports."""

NAME = "Your Name"
ADDRESS = "Your Street and Number"
ZIP_CITY = "12345 Your City"
PHONE_NUMBER = "+49 123 4567890"
CUSTOMER_NR = "Your customer number"
CONTRACT_NR = "Your contract number"
```

| Field          | Purpose                                              |
|----------------|------------------------------------------------------|
| `NAME`         | Full name of the account holder                      |
| `ADDRESS`      | Street address                                       |
| `ZIP_CITY`     | ZIP code and city                                    |
| `PHONE_NUMBER` | Contact phone number                                 |
| `CUSTOMER_NR`  | ISP customer/account number                          |
| `CONTRACT_NR`  | ISP contract/service number                          |

### Running

```bash
python main.py
```

- A GUI window will appear showing live connection status, latency, and DNS.
- The monitor runs **indefinitely** until you close the window or press `Ctrl+C` in the terminal.
- Click **"Save Report Now"** at any time to update today's PDF report.
- The PDF is automatically updated at midnight and when the monitor stops.
- The PDF (`internet_report.pdf`) is overwritten on each save with the latest data.

### Output Files

| File                                    | Description                          |
|-----------------------------------------|--------------------------------------|
| `internet_report.pdf`                   | Report (overwritten on each save)    |
| `connection_log.jsonl`                  | Event log (appended on restart)      |

---

## Configuration Options

All configuration is in `config.py`:

```python
CHECK_INTERVAL = 5          # seconds between connectivity checks
PING_TARGETS = [            # multiple targets for robust detection
    ("1.1.1.1", 53),        # Cloudflare DNS
    ("8.8.8.8", 53),        # Google DNS
    ("9.9.9.9", 53),        # Quad9 DNS
]
PING_TIMEOUT = 3            # seconds before a check is considered failed
DNS_TEST_DOMAIN = "google.com"
LOG_CHECK_EVERY = 12        # log a periodic "check" every N cycles (60s default)

# Gateway / Router diagnostics
GATEWAY_CHECK_ENABLED = True     # check gateway reachability on each cycle
GATEWAY_IP = ""                  # auto-detect if empty; set e.g. "192.168.178.1"
GATEWAY_TIMEOUT = 2              # seconds

# SNMP router monitoring (optional)
SNMP_ENABLED = False             # set True to poll router via SNMPv2c
SNMP_HOST = "192.168.178.1"      # router IP
SNMP_TIMEOUT = 2                 # seconds
SNMP_INTERFACE_INDEX = 1         # ifIndex of the WAN interface
# Community string loaded from SNMP_COMMUNITY env var, default "public"
```

| Setting                  | Default           | Notes                                            |
|--------------------------|-------------------|--------------------------------------------------|
| `CHECK_INTERVAL`         | `5`               | Lower = more precise but more network traffic    |
| `PING_TARGETS`           | 3 DNS servers     | Add/remove targets as needed                     |
| `PING_TIMEOUT`           | `3`               | Increase on very slow connections                |
| `DNS_TEST_DOMAIN`        | `google.com`      | Any reliably resolvable domain                   |
| `LOG_CHECK_EVERY`        | `12`              | Periodic log frequency (12 x 5s = 60s)           |
| `GATEWAY_CHECK_ENABLED`  | `True`            | Enable/disable gateway reachability checking     |
| `GATEWAY_IP`             | `""` (auto-detect) | Set manually if auto-detection fails             |
| `GATEWAY_TIMEOUT`        | `2`               | Seconds before gateway check is considered failed|
| `SNMP_ENABLED`           | `False`           | Set `True` to poll router via SNMPv2c            |
| `SNMP_HOST`              | `192.168.178.1`   | Router IP address for SNMP queries               |
| `SNMP_PORT`              | `161`             | Standard SNMP port                               |
| `SNMP_COMMUNITY`         | `public`          | SNMPv2c community string (from `SNMP_COMMUNITY` env var) |
| `SNMP_TIMEOUT`           | `2`               | Seconds before SNMP query times out              |
| `SNMP_INTERFACE_INDEX`   | `1`               | ifIndex of the WAN interface to monitor          |

---

## File Structure

```
ICIM/
├── main.py                          # Entry point
├── monitor.py                       # Core InternetMonitor class (event loop, state machine, JSONL logging)
├── gui.py                           # Tkinter dashboard (MonitorGUI)
├── network.py                       # TCP connectivity checks, gateway check, public/local IP, metadata
├── dns.py                           # Raw UDP DNS query construction, parsing, and resolution testing
├── snmp.py                          # Raw SNMPv2c GET - router counter polling (no external deps)
├── report.py                        # PDF report generation with fpdf2 and SHA-256 integrity hash
├── config.py                        # All tunable constants (intervals, targets, timeouts, filenames)
├── user.py                          # User/contract details for PDF reports (NOT in repo, see README)
├── text.py                          # Centralized user-facing text strings for all modules
├── utils.py                         # Shared helpers (format_duration, pdf_safe, snmp_safe)
├── pyproject.toml                   # Project metadata and dependencies
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
├── LICENSE                          # GPL-3.0 license text
├── .gitignore                       # Git ignore rules
├── connection_log.jsonl             # Real-time event log (appended across restarts)
├── .ipinfo_cert_pin                 # TLS certificate pin for ipinfo.io (TOFU, generated at runtime)
└── internet_report.pdf              # PDF report (overwritten on each save)
```

---

## Glossary

| Term            | Definition                                                              |
|-----------------|-------------------------------------------------------------------------|
| **TCP**         | Transmission Control Protocol - a reliable connection-oriented protocol |
| **DNS**         | Domain Name System - translates domain names to IP addresses            |
| **ISP**         | Internet Service Provider - the company providing internet access       |
| **ISDN**        | Integrated Services Digital Network - a legacy digital telephone line technology, an atrocity author of this software is subjected to. In 2026. Yes. |
| **Outage**      | A period during which the internet connection is non-functional         |
| **Uptime**      | The percentage of total monitoring time during which the connection worked |
| **Latency**     | The time delay for a network packet to travel to a server and back      |
| **P50/P95**     | Percentile values - P50 is the median, P95 is the 95th percentile      |
| **Public IP**   | The IP address visible to external servers, assigned by the ISP         |
| **Local IP**    | The IP address assigned to the device on the local network (LAN)        |
| **SLA**         | Service Level Agreement - contractual uptime/quality guarantees         |
| **QoS**         | Quality of Service - measurable service performance metrics             |
| **SHA-256**     | A cryptographic hash function producing a unique 256-bit fingerprint    |
| **JSONL**       | JSON Lines - a format where each line is a valid JSON object            |
| **SNMP**        | Simple Network Management Protocol - queries device counters/status    |
| **SPKI**        | Subject Public Key Info - the public key portion of a TLS certificate  |
| **TOFU**        | Trust On First Use - learn a credential on first contact, verify after |
| **Gateway**     | The default router connecting the LAN to the ISP's network             |
| **ifIndex**     | SNMP interface index identifying a specific network port on the router |
| **OID**         | Object Identifier - the SNMP address of a specific counter or status   |

---

## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0).

You are free to use, modify, and distribute this software under the terms of the
GPL-3.0. See the [LICENSE](LICENSE) file for the full license text, or visit
<https://www.gnu.org/licenses/gpl-3.0.html>.

```
Internet Connection Interruption Monitor
Copyright (C) 2026 ThePineappleExpress

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
```

---
