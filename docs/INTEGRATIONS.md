# Integrating PhishHawk

PhishHawk is a command-line tool with machine-readable output, so it fits into
most SOC stacks without a plugin. This page shows the common routes. Each
platform's menus and APIs change between versions, so treat the snippets as
starting points and check them against your own instance.

- [Which export for which tool](#which-export-for-which-tool)
- [Threat-intelligence platforms](#threat-intelligence-platforms)
  - [MISP](#misp)
  - [OpenCTI](#opencti)
  - [Microsoft Sentinel](#microsoft-sentinel)
- [SIEM](#siem)
  - [Splunk](#splunk)
  - [Elastic](#elastic)
- [Case management: TheHive](#case-management-thehive)
- [SOAR playbooks](#soar-playbooks)
- [Polling a phishing-report mailbox](#polling-a-phishing-report-mailbox)
- [Scheduled runs](#scheduled-runs)
- [Using PhishHawk as a Python library](#using-phishhawk-as-a-python-library)

## Which export for which tool

```mermaid
flowchart LR
    PH["phishhawk scan"] --> J["--json"]
    PH --> X["--stix"]
    PH --> C["--csv"]
    PH --> M["--md"]
    PH --> H["--html"]
    PH --> MI["--misp"]
    MI --> MISP["MISP"]
    J --> SOAR["SOAR playbooks<br/>XSOAR, Splunk SOAR,<br/>Shuffle, Tines"]
    J --> SIEM["SIEM events<br/>Splunk HEC, Elastic"]
    X --> TIP["Threat intel<br/>OpenCTI, Sentinel TI,<br/>MISP"]
    C --> BL["Block lists and<br/>SIEM lookups"]
    M --> CASE["Tickets<br/>TheHive, Jira,<br/>ServiceNow"]
    H --> PEOPLE["People<br/>L2, managers,<br/>the reporter"]
```

| Export | Shape | Good for |
|---|---|---|
| `--json` | One object per message (or `{"reports": [...]}`) with verdict, signals, techniques, indicators and actions | Anything that makes decisions |
| `--stix` | STIX 2.1 bundle: an `identity`, one `indicator` per IOC, `attack-pattern` objects for the ATT&CK techniques and a `report` per message | Sharing intelligence |
| `--misp` | A MISP event per message: attributes for every indicator, an `email` object, ATT&CK galaxy tags and a TLP tag | MISP |
| `--csv` | `type, value, defanged, context, verdict, subject, source_file` | Block lists, lookups, spreadsheets |
| `--md` | Ticket note: headers, key findings, defanged indicator table, ATT&CK, action checklist | Case notes |
| `--html` | Self-contained page with a strict Content-Security-Policy | Attaching to a ticket or email |

STIX indicators carry a `confidence` that follows the verdict (85 for
`MALICIOUS`, 70 for `LIKELY PHISHING`, 40 for `SUSPICIOUS`) and
`indicator_types` of `malicious-activity` or `anomalous-activity`. Object IDs
are derived from the indicator value, so importing the same URL twice updates
one object instead of creating two.

## Threat-intelligence platforms

### MISP

`--misp event.json` writes a native MISP event: every indicator as an
attribute (URLs, domains, `ip-src` for the sending IP, `email-src` and
`email-reply-to`, `sha256` and `filename|sha256`, `btc`/`xmr` wallets, phone
numbers), an `email` object with the subject, sender and Message-ID, the ATT&CK
techniques as `misp-galaxy:mitre-attack-pattern` tags, `rsit:fraud="phishing"`,
and a TLP tag (`--tlp`, default `amber`). The event's distribution is "your
organisation only" until someone decides otherwise. UUIDs are derived from the
content, so importing the same message twice updates one event.

In the web interface use *Add Event → Populate from JSON*, or with
[PyMISP](https://github.com/MISP/PyMISP):

```python
import json
from pymisp import MISPEvent, PyMISP

misp = PyMISP("https://misp.example.com", "YOUR_API_KEY")
data = json.load(open("event.json"))
for item in data if isinstance(data, list) else [data]:  # a batch writes a list of events
    event = MISPEvent()
    event.load(item)
    misp.add_event(event)
```

A STIX bundle from `--stix` can also be imported, with *Import from… → STIX 2.x*.

### OpenCTI

Upload the bundle under *Data → Import* (the STIX file import connector must be
enabled), or push it with [pycti](https://github.com/OpenCTI-Platform/client-python):

```python
from pycti import OpenCTIApiClient

client = OpenCTIApiClient("https://opencti.example.com", "YOUR_API_TOKEN")
client.stix2.import_bundle_from_file("bundle.json")
```

The `report` objects arrive as OpenCTI reports with the indicators and ATT&CK
attack patterns attached.

### Microsoft Sentinel

Sentinel's threat-intelligence page can import indicators from a file (STIX
JSON or CSV). Use the `--stix` bundle, or reshape the CSV to the column layout
your Sentinel version asks for. For a continuous feed, send the JSON output to a
Logic App or Azure Function that calls the threat-intelligence upload API.

## SIEM

### Splunk

**Hunt for clicks.** Load the CSV as a lookup, then search proxy logs for anyone
who visited a reported domain:

```bash
phishhawk scan reported/ --csv phishhawk_iocs.csv
# copy it to $SPLUNK_HOME/etc/apps/search/lookups/, or upload it under
# Settings → Lookups → Lookup table files
```

```spl
index=proxy
    [| inputlookup phishhawk_iocs.csv
     | where type="domain"
     | rename value AS dest_host
     | fields dest_host]
| stats count values(user) AS users BY dest_host
```

**Index every triage** through the HTTP Event Collector, so verdicts can be
reported on:

```bash
phishhawk scan mail.eml --json - \
  | jq -c '{sourcetype: "phishhawk:triage", event: .}' \
  | curl -sS https://splunk.example.com:8088/services/collector/event \
         -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" --data-binary @-
```

### Elastic

Send one document per triage with the bulk API:

```bash
phishhawk scan reported/ --json - \
  | jq -c '(.reports // [.])[] | {"index": {"_index": "phishhawk"}}, .' \
  | curl -sS -H "Content-Type: application/x-ndjson" -u "$ES_USER:$ES_PASS" \
         -X POST "https://elastic.example.com:9200/_bulk" --data-binary @-
```

## Case management: TheHive

Use the Markdown report as the case or alert description, and turn the JSON
indicators into observables. A minimal sketch for TheHive 5's API:

```python
import json, subprocess, requests

THEHIVE = "https://thehive.example.com"
HEADERS = {"Authorization": "Bearer YOUR_API_KEY"}
DATA_TYPES = {"url": "url", "domain": "domain", "ipv4": "ip", "email": "mail", "sha256": "hash"}

eml = "reported/ticket-4821.eml"
run = subprocess.run(["phishhawk", "scan", eml, "--json", "-", "--no-banner"],
                     capture_output=True, text=True)
report = json.loads(run.stdout)
note = subprocess.run(["phishhawk", "scan", eml, "--md", "-", "--no-banner"],
                      capture_output=True, text=True).stdout

alert = {
    "type": "phishing-report",
    "source": "phishhawk",
    "sourceRef": report["message_id"] or eml,
    "title": "%s: %s" % (report["verdict"], report["subject"]),
    "description": note,
    "severity": {"MALICIOUS": 3, "LIKELY PHISHING": 3, "SUSPICIOUS": 2}.get(report["verdict"], 1),
    "tags": ["phishing"] + [t["id"] for t in report["techniques"]],
    "observables": [{"dataType": DATA_TYPES[i["type"]], "data": i["value"], "message": i["context"]}
                    for i in report["iocs"] if i["type"] in DATA_TYPES],
}
requests.post(THEHIVE + "/api/v1/alert", json=alert, headers=HEADERS, timeout=30).raise_for_status()
```

The second run is served from PhishHawk's cache, so it costs no extra API calls.

## SOAR playbooks

Any SOAR platform that can run a command (Cortex XSOAR, Splunk SOAR, Shuffle,
Tines, n8n …) can drive PhishHawk the same way:

1. Save the reported message as a `.eml` file.
2. Run `phishhawk scan "$EML" --json - --no-banner`.
3. Branch on the **exit code**: `0` close, `1` send to an analyst, `2` open an
   incident, `3` the input was unreadable.
4. Use `iocs[]` for block actions, `recommendations[]` for the task list and
   `techniques[]` for tagging.

```bash
report=$(phishhawk scan "$EML" --json - --no-banner)
status=$?
verdict=$(jq -r .verdict <<<"$report")
case $status in
  0) echo "close: $verdict" ;;
  1) echo "assign to analyst: $verdict" ;;
  2) echo "open incident: $verdict" ;;
  *) echo "could not analyse $EML" >&2 ;;
esac
```

## Polling a phishing-report mailbox

Many organisations route "Report phishing" clicks to a shared mailbox.
`phishhawk imap` reads it directly, read-only, so nothing is marked read,
moved or deleted:

```bash
export PHISHHAWK_IMAP_PASSWORD='...'      # or PHISHHAWK_IMAP_TOKEN for OAuth (Microsoft 365, Gmail)
phishhawk imap --host outlook.office365.com --user soc@example.com \
  --folder "Phish reports" --watch 300 --quiet --out /srv/phishing/reports --misp /srv/phishing/latest.json
```

Every five minutes it triages what arrived since the last round, writes a JSON
and an HTML report per message, and keeps going if the server drops the
connection. See [the usage guide](USAGE.md#imap-triage-a-mailbox-folder).

To do the same from Python, `phishhawk.imapfetch.fetch()` yields each message's
raw bytes:

```python
from phishhawk.imapfetch import ImapSource, fetch
from phishhawk.pipeline import Options, triage_bytes

source = ImapSource(host="imap.example.com", user="soc", password="...", folder="Phish reports", unseen=True)
for label, uid, data in fetch(source, max_bytes=50 * 1024 * 1024):
    if isinstance(data, Exception):
        print(label, "skipped:", data)
        continue
    analysis = triage_bytes(data, path=label, options=Options(protected=["example.com"]))
    print(analysis.verdict, analysis.score, analysis.subject)
```

Where IMAP is switched off, as in many Microsoft 365 and Google Workspace
tenants, `phishhawk graph` and `phishhawk gmail` read the same mailbox through
Microsoft Graph or the Gmail API, with the same options and the same read-only
promise: only `GET` requests, so nothing is marked read, moved or deleted.

```bash
export PHISHHAWK_GRAPH_TOKEN='...'        # a token with Mail.Read; PHISHHAWK_GMAIL_TOKEN (gmail.readonly) for gmail
phishhawk graph --mailbox soc@example.com --folder "Phish reports" \
  --watch 300 --quiet --out /srv/phishing/reports --misp /srv/phishing/latest.json
```

From Python, `phishhawk.mailapi.fetch_graph()` and `fetch_gmail()` yield
`(label, message id, raw bytes or the reason it was skipped)` like
`imapfetch.fetch()`. See [the usage guide](USAGE.md#graph-and-gmail-triage-a-mailbox-through-its-api).

Because users usually report the phish **as an attachment** (an `.eml`, or an
`.msg` from Outlook's button), PhishHawk analyses the attached original and
records who reported it in `reported_by`.

## Scoping and response: campaigns, sweeps, evidence and sandboxes

PhishHawk reads and reports; your mail platform, SOAR and EDR act. A typical
incident runs like this:

```bash
CASE=/cases/4711
phishhawk scan reported/ --quiet --evidence "$CASE" --sandbox "$CASE/sandbox" --json "$CASE/triage.json"
phishhawk campaign reported/ --json "$CASE/campaigns.json" --md "$CASE/campaigns.md"
phishhawk sweep graph --like reported/first.eml --mailboxes staff.txt --json "$CASE/copies.json"
phishhawk evidence verify "$CASE"
```

- **Purge and block** with `copies.json` (each copy's mailbox and message id)
  and `triage.json`'s `iocs[]`: a SOAR playbook can delete the copies through
  Graph or the Gmail API with its own, separately approved, write permission.
  Review any copy matched only by "(Gmail's search, not checked again)", and
  treat an incomplete sweep (exit `3`) as unfinished.
- **Who clicked** is not in a mailbox: search your proxy, DNS and EDR logs for
  the domains and SHA-256 values in `iocs[]`.
- **Detonate** with the pack in `$CASE/sandbox`: CAPE, Joe Sandbox, ANY.RUN
  and Hybrid Analysis all accept a ZIP with the password `infected`, and
  `urls.txt` inside lists the links to submit as URL tasks.
- **Keep the chain of custody**: put `evidence verify`'s `head`, or each
  report's `evidence.custody`, in the ticket, and check the folder against it
  later with `phishhawk evidence verify "$CASE" --head <value>`.

**Sweeping many Microsoft 365 mailboxes** needs an application (not delegated)
token with the `Mail.Read` application permission. Grant it to an app
registration and restrict it to the mailboxes you sweep with an
[application access policy](https://learn.microsoft.com/graph/auth-limit-mailbox-access);
`az account get-access-token --resource-type ms-graph` is enough for your own
mailbox. **Gmail tokens belong to one mailbox**: with domain-wide delegation
and the `gmail.readonly` scope, mint one per mailbox and run `sweep gmail
--mailbox user@example.com` for each.

```bash
# exit 0: no other copy; 1: copies found; 3: a mailbox could not be searched
phishhawk sweep graph --like "$EML" --mailboxes staff.txt --json - > copies.json
case $? in 0) echo "contained" ;; 1) echo "purge $(jq .found copies.json) copies" ;; *) echo "sweep incomplete" ;; esac
```

## Scheduled runs

A script that triages each new file in a drop folder, keeps one HTML and CSV
report per message and moves the message out of the way:

```bash
#!/usr/bin/env bash
# /srv/phishing/triage.sh, run from cron:  */15 * * * *  /srv/phishing/triage.sh
cd /srv/phishing || exit 1
for eml in inbox/*.eml; do
  [ -e "$eml" ] || continue
  name=$(basename "$eml" .eml)
  phishhawk scan "$eml" --quiet --no-banner \
    --html "out/$name.html" --csv "out/$name.csv" >> phishhawk.log 2>&1
  mv "$eml" done/
done
```

The cache makes repeated runs cheap: an indicator already looked up in the last
24 hours costs nothing. For a mailbox rather than a folder, `phishhawk imap
--watch` does the same without cron.

## Using PhishHawk as a Python library

The command line is the stable interface. The Python API below is what the CLI
itself uses and is handy for scripts, but it may change between minor versions.

```python
from phishhawk.pipeline import Options, triage_file
from phishhawk.report.common import to_dict

analysis = triage_file("suspicious.eml", Options(protected=["example.com"]))
print(analysis.verdict, analysis.score)          # LIKELY PHISHING 32
for signal in analysis.signals:
    print(signal.severity, signal.label, signal.techniques)
for ioc in analysis.iocs():
    print(ioc["type"], ioc["value"])
report = to_dict(analysis)                       # the same dict as --json
```

With reputation lookups and the shared cache:

```python
import os
from phishhawk.cache import Cache, default_cache_path
from phishhawk.enrich import Enricher, Rdap, VirusTotal
from phishhawk.pipeline import triage_file

cache = Cache(default_cache_path())
enricher = Enricher(virustotal=VirusTotal(os.environ["VT_API_KEY"], cache=cache),
                    rdap=Rdap(cache=cache))
analysis = triage_file("suspicious.eml", enricher=enricher)
```

`triage_bytes(data, path=...)` does the same for a message already in memory.
