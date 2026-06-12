# Palisade — detection engineering platform

A self-contained threat-detection platform with three parts:

1. **Server / console** (`server/`) — FastAPI app that hosts a Sigma-style
   detection library, translates each detection into vendor query languages
   (Splunk SPL, Microsoft Sentinel KQL, Elastic, CrowdStrike LogScale),
   manages an agent fleet, and ingests alerts. Ships with a web console.
2. **Agent** (`agent/`) — a dependency-light Python sensor for **Windows,
   Linux, and macOS**. It enrolls, pulls the detections relevant to its OS,
   evaluates them against local process and file telemetry, and reports alerts.
3. **Installers** (`install/`) — systemd (Linux), launchd (macOS), and a
   scheduled-task PowerShell script (Windows).

```
 ┌────────────┐   enroll / tasking / alerts   ┌──────────────────────────┐
 │  Agents    │  ───────── HTTPS ──────────▶   │  Palisade server          │
 │ win/lin/mac│                                │  • detection library      │
 └────────────┘                                │  • vendor translation     │
       ▲                                        │  • fleet + alert store    │
       │  compiled rules for this OS            │  • web console            │
       └────────────────────────────────────────┘
                                                 │ exports queries to
                                                 ▼  SIEM / EDR vendors
                              Splunk · Sentinel · Elastic · CrowdStrike
```

## Run the server

```bash
cd server
python3 -m pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8787
```

Open the console at `http://localhost:8787`. The library is seeded with 12
detections spanning Windows, Linux, and macOS across multiple ATT&CK tactics.

## Install an agent

Point each endpoint at your server URL.

**Linux** (systemd, as root):
```bash
sudo install/install_linux.sh http://YOUR-SERVER:8787
```

**macOS** (launchd, as root):
```bash
sudo install/install_macos.sh http://YOUR-SERVER:8787
```

**Windows** (elevated PowerShell, requires Python 3 on PATH):
```powershell
.\install\install_windows.ps1 -Server http://YOUR-SERVER:8787
```

To try it without installing a service:
```bash
pip install psutil
python3 agent/palisade_agent.py --server http://localhost:8787
```

The agent appears under **Fleet** within ~15s; anything that trips a rule shows
up under **Alerts**.

## How detections work

Detections use a small Sigma-like schema:

```json
{
  "rule_id": "PAL-W-0001",
  "title": "Encoded PowerShell Command Execution",
  "severity": "high",
  "platforms": ["windows"],
  "logsource": {"category": "process_creation"},
  "detection": {
    "selection": [
      {"field": "Image", "modifier": "endswith", "values": ["\\powershell.exe"]},
      {"field": "CommandLine", "modifier": "contains", "values": ["-enc"]}
    ],
    "filter": [ ... optional allowlist ... ],
    "condition": "selection and not filter"
  },
  "attack": {"tactics": ["execution"], "techniques": ["T1059.001"]}
}
```

Supported field modifiers: `equals`, `contains`, `startswith`, `endswith`, `re`.
Canonical fields (`Image`, `CommandLine`, `ParentImage`, `User`,
`TargetFilename`) are mapped per-vendor by the translation engine, so the same
rule yields correct SPL, KQL, Elastic, and LogScale queries.

### Add a detection

```bash
curl -X POST http://localhost:8787/api/detections \
  -H 'Content-Type: application/json' \
  -d @my_rule.json
```

## Vendor coverage

The translation engine targets four backends today:

| Vendor       | Output            | Source category mapping            |
|--------------|-------------------|------------------------------------|
| Splunk       | SPL               | Sysmon EventCode 1/11              |
| Sentinel     | KQL               | DeviceProcessEvents / DeviceFileEvents |
| Elastic      | Lucene/KQL        | ECS (`process.*`, `file.*`)        |
| CrowdStrike  | Falcon LogScale   | ProcessRollup2 / file-write events |

This is a transparent, reviewable translator over a constrained field set. For
production breadth you would swap in pySigma with vendor backends; the schema
above is intentionally Sigma-compatible to make that migration straightforward.

## API reference

| Method | Path                                          | Purpose                       |
|--------|-----------------------------------------------|-------------------------------|
| GET    | `/api/detections`                             | list / filter the library     |
| POST   | `/api/detections`                             | add a detection               |
| GET    | `/api/detections/{id}/translate?target=…`     | compile to a vendor query     |
| PATCH  | `/api/detections/{id}`                        | enable / disable              |
| GET    | `/api/coverage`                               | detections per ATT&CK tactic  |
| POST   | `/api/agents/enroll`                          | agent enrollment              |
| GET    | `/api/agents/{id}/tasking`                    | rules compiled for that OS    |
| POST   | `/api/agents/{id}/alerts`                     | report an alert               |
| GET    | `/api/agents` · `/api/alerts`                 | fleet and alert feeds         |

## Security notes / honest limits

- Agent auth is a per-agent bearer key issued at enrollment. Put the server
  behind TLS (a reverse proxy) before exposing it; enrollment is currently open.
- The agent approximates process-creation events with periodic `psutil`
  snapshots. Production-grade sensors use ETW (Windows), eBPF/auditd (Linux),
  and the Endpoint Security framework (macOS) for real-time, no-gap capture.
- Telemetry is process + file-write today. Network, registry, and authentication
  sources are the natural next collectors.
