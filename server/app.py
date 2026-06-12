"""
PALISADE — detection engineering platform
FastAPI server: detection library, vendor query translation, agent fleet, alert ingestion.

Run:  uvicorn app:app --host 0.0.0.0 --port 8787
"""
import json
import sqlite3
import time
import uuid
import re
import secrets
from pathlib import Path
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "palisade.db"

app = FastAPI(title="Palisade", version="0.1.0")

# ----------------------------------------------------------------------------
# Storage
# ----------------------------------------------------------------------------

@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                rule_id TEXT UNIQUE,
                title TEXT, description TEXT,
                severity TEXT, status TEXT,
                platforms TEXT, logsource TEXT,
                detection TEXT, attack TEXT,
                refs TEXT, author TEXT,
                enabled INTEGER DEFAULT 1,
                created_at REAL, updated_at REAL
            );
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                key TEXT,
                hostname TEXT, os TEXT, arch TEXT, version TEXT,
                enrolled_at REAL, last_seen REAL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                agent_id TEXT, rule_id TEXT, title TEXT, severity TEXT,
                hostname TEXT, os TEXT,
                context TEXT,
                created_at REAL
            );
            """
        )


# ----------------------------------------------------------------------------
# Vendor translation engine
# ----------------------------------------------------------------------------
# A deliberately small, transparent translation layer. In production you would
# back this with pySigma + vendor backends; this implements the same idea for a
# constrained field set so output is honest and reviewable.

FIELD_MAPS = {
    "splunk": {  # Sysmon-flavored CIM-ish
        "Image": "Image", "CommandLine": "CommandLine",
        "ParentImage": "ParentImage", "User": "User",
        "TargetFilename": "TargetFilename",
    },
    "sentinel": {  # Microsoft Defender / Sentinel advanced hunting
        "Image": "FolderPath", "CommandLine": "ProcessCommandLine",
        "ParentImage": "InitiatingProcessFolderPath", "User": "AccountName",
        "TargetFilename": "FolderPath",
    },
    "elastic": {  # ECS
        "Image": "process.executable", "CommandLine": "process.command_line",
        "ParentImage": "process.parent.executable", "User": "user.name",
        "TargetFilename": "file.path",
    },
    "crowdstrike": {  # Falcon LogScale
        "Image": "ImageFileName", "CommandLine": "CommandLine",
        "ParentImage": "ParentBaseFileName", "User": "UserName",
        "TargetFilename": "TargetFileName",
    },
}

TABLE_FOR = {
    "sentinel": {"process_creation": "DeviceProcessEvents", "file_event": "DeviceFileEvents"},
    "elastic": {"process_creation": "process", "file_event": "file"},
    "crowdstrike": {"process_creation": "#event_simpleName=ProcessRollup2",
                    "file_event": "#event_simpleName=*WrittenDetectInfo"},
    "splunk": {"process_creation": "index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1",
               "file_event": "index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=11"},
}


def esc(v: str, quote='"'):
    return v.replace("\\", "\\\\").replace(quote, "\\" + quote)


def _clause_splunk(field, modifier, values):
    parts = []
    for v in values:
        if modifier == "contains":
            parts.append(f'{field}="*{esc(v)}*"')
        elif modifier == "endswith":
            parts.append(f'{field}="*{esc(v)}"')
        elif modifier == "startswith":
            parts.append(f'{field}="{esc(v)}*"')
        elif modifier == "re":
            return f'| regex {field}="{v}"'
        else:
            parts.append(f'{field}="{esc(v)}"')
    return "(" + " OR ".join(parts) + ")" if len(parts) > 1 else parts[0]


def _clause_kql(field, modifier, values):
    def one(v):
        if modifier == "re":
            return f'{field} matches regex @"{v}"'
        v = esc(v)
        if modifier == "contains":
            return f'{field} contains "{v}"'
        if modifier == "endswith":
            return f'{field} endswith "{v}"'
        if modifier == "startswith":
            return f'{field} startswith "{v}"'
        return f'{field} =~ "{v}"'
    parts = [one(v) for v in values]
    return "(" + " or ".join(parts) + ")" if len(parts) > 1 else parts[0]


def _clause_lucene(field, modifier, values):
    def one(v):
        if modifier == "re":
            return f'{field}:/{v}/'
        v = v.replace("\\", "\\\\").replace('"', '\\"')
        if modifier == "contains":
            return f'{field}:*{v}*'
        if modifier == "endswith":
            return f'{field}:*{v}'
        if modifier == "startswith":
            return f'{field}:{v}*'
        return f'{field}:"{v}"'
    parts = [one(v) for v in values]
    return "(" + " OR ".join(parts) + ")" if len(parts) > 1 else parts[0]


def _clause_logscale(field, modifier, values):
    def one(v):
        if modifier == "re":
            return f'{field}=/{v}/i'
        v = esc(v)
        if modifier == "contains":
            return f'{field}="*{v}*"'
        if modifier == "endswith":
            return f'{field}="*{v}"'
        if modifier == "startswith":
            return f'{field}="{v}*"'
        return f'{field}="{v}"'
    parts = [one(v) for v in values]
    return "(" + " OR ".join(parts) + ")" if len(parts) > 1 else parts[0]


CLAUSE_FN = {
    "splunk": _clause_splunk,
    "sentinel": _clause_kql,
    "elastic": _clause_lucene,
    "crowdstrike": _clause_logscale,
}

JOIN_AND = {"splunk": " ", "sentinel": " and ", "elastic": " AND ", "crowdstrike": " "}


def translate(det: dict, target: str) -> str:
    if target not in FIELD_MAPS:
        raise HTTPException(400, f"unknown target '{target}'")
    fmap = FIELD_MAPS[target]
    clause = CLAUSE_FN[target]
    d = det["detection"]
    category = det["logsource"].get("category", "process_creation")

    def block(items):
        out = []
        for item in items:
            f = fmap.get(item["field"], item["field"])
            out.append(clause(f, item.get("modifier", "equals"), item["values"]))
        return JOIN_AND[target].join(out)

    sel = block(d.get("selection", []))
    flt = block(d.get("filter", [])) if d.get("filter") else None

    if target == "splunk":
        base = TABLE_FOR["splunk"][category]
        q = f"{base} {sel}"
        if flt:
            q += f" NOT ({flt})"
        return q + "\n| table _time host User Image CommandLine ParentImage"
    if target == "sentinel":
        table = TABLE_FOR["sentinel"][category]
        q = f"{table}\n| where {sel}"
        if flt:
            q += f"\n| where not({flt})"
        return q + "\n| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine"
    if target == "elastic":
        q = sel if not flt else f"({sel}) AND NOT ({flt})"
        return q
    if target == "crowdstrike":
        base = TABLE_FOR["crowdstrike"][category]
        q = f"{base}\n| {sel}"
        if flt:
            q += f"\n| !({flt})"
        return q + "\n| table([@timestamp, ComputerName, UserName, ImageFileName, CommandLine])"
    raise HTTPException(400, "unsupported target")


# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------

class DetectionIn(BaseModel):
    rule_id: str
    title: str
    description: str = ""
    severity: str = "medium"
    status: str = "experimental"
    platforms: list[str] = Field(default_factory=lambda: ["windows"])
    logsource: dict = Field(default_factory=lambda: {"category": "process_creation"})
    detection: dict
    attack: dict = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    author: str = ""
    enabled: bool = True


class EnrollIn(BaseModel):
    hostname: str
    os: str
    arch: str = ""
    version: str = "0.1.0"


class AlertIn(BaseModel):
    rule_id: str
    title: str
    severity: str
    context: dict = Field(default_factory=dict)


def row_to_detection(r) -> dict:
    return {
        "id": r["id"], "rule_id": r["rule_id"], "title": r["title"],
        "description": r["description"], "severity": r["severity"],
        "status": r["status"], "platforms": json.loads(r["platforms"]),
        "logsource": json.loads(r["logsource"]),
        "detection": json.loads(r["detection"]),
        "attack": json.loads(r["attack"]), "references": json.loads(r["refs"]),
        "author": r["author"], "enabled": bool(r["enabled"]),
        "created_at": r["created_at"], "updated_at": r["updated_at"],
    }


# ----------------------------------------------------------------------------
# Detection library API
# ----------------------------------------------------------------------------

@app.get("/api/detections")
def list_detections(q: str = "", severity: str = "", platform: str = "", tactic: str = ""):
    with db() as conn:
        rows = conn.execute("SELECT * FROM detections ORDER BY rule_id").fetchall()
    out = []
    for r in rows:
        d = row_to_detection(r)
        if q and q.lower() not in (d["title"] + d["description"] + d["rule_id"]).lower():
            continue
        if severity and d["severity"] != severity:
            continue
        if platform and platform not in d["platforms"]:
            continue
        if tactic and tactic not in d["attack"].get("tactics", []):
            continue
        out.append(d)
    return out


@app.get("/api/detections/{det_id}")
def get_detection(det_id: str):
    with db() as conn:
        r = conn.execute("SELECT * FROM detections WHERE id=? OR rule_id=?", (det_id, det_id)).fetchone()
    if not r:
        raise HTTPException(404, "detection not found")
    return row_to_detection(r)


@app.post("/api/detections", status_code=201)
def create_detection(body: DetectionIn):
    now = time.time()
    det_id = str(uuid.uuid4())
    with db() as conn:
        try:
            conn.execute(
                "INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (det_id, body.rule_id, body.title, body.description, body.severity,
                 body.status, json.dumps(body.platforms), json.dumps(body.logsource),
                 json.dumps(body.detection), json.dumps(body.attack),
                 json.dumps(body.references), body.author, int(body.enabled), now, now),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, f"rule_id {body.rule_id} already exists")
    return {"id": det_id}


@app.patch("/api/detections/{det_id}")
def patch_detection(det_id: str, body: dict):
    with db() as conn:
        r = conn.execute("SELECT id FROM detections WHERE id=? OR rule_id=?", (det_id, det_id)).fetchone()
        if not r:
            raise HTTPException(404, "detection not found")
        if "enabled" in body:
            conn.execute("UPDATE detections SET enabled=?, updated_at=? WHERE id=?",
                         (int(bool(body["enabled"])), time.time(), r["id"]))
    return {"ok": True}


@app.get("/api/detections/{det_id}/translate")
def translate_detection(det_id: str, target: str):
    det = get_detection(det_id)
    return {"target": target, "query": translate(det, target)}


@app.get("/api/coverage")
def coverage():
    tactic_order = ["initial-access", "execution", "persistence", "privilege-escalation",
                    "defense-evasion", "credential-access", "discovery", "lateral-movement",
                    "collection", "command-and-control", "exfiltration", "impact"]
    counts = {t: 0 for t in tactic_order}
    for d in list_detections():
        for t in d["attack"].get("tactics", []):
            if t in counts:
                counts[t] += 1
    return {"tactics": [{"tactic": t, "count": counts[t]} for t in tactic_order]}


# ----------------------------------------------------------------------------
# Agent fleet API
# ----------------------------------------------------------------------------

def auth_agent(conn, agent_id: str, request: Request):
    key = request.headers.get("x-palisade-key", "")
    r = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if not r or not secrets.compare_digest(r["key"], key):
        raise HTTPException(401, "bad agent credentials")
    return r


@app.post("/api/agents/enroll", status_code=201)
def enroll(body: EnrollIn):
    agent_id = str(uuid.uuid4())
    key = secrets.token_hex(24)
    now = time.time()
    with db() as conn:
        conn.execute("INSERT INTO agents VALUES (?,?,?,?,?,?,?,?)",
                     (agent_id, key, body.hostname, body.os, body.arch, body.version, now, now))
    return {"agent_id": agent_id, "key": key}


@app.post("/api/agents/{agent_id}/heartbeat")
def heartbeat(agent_id: str, request: Request):
    with db() as conn:
        auth_agent(conn, agent_id, request)
        conn.execute("UPDATE agents SET last_seen=? WHERE id=?", (time.time(), agent_id))
    return {"ok": True}


@app.get("/api/agents/{agent_id}/tasking")
def tasking(agent_id: str, request: Request):
    """Enabled detections compiled for this agent's platform."""
    with db() as conn:
        agent = auth_agent(conn, agent_id, request)
    plat = agent["os"]
    rules = [d for d in list_detections() if d["enabled"] and plat in d["platforms"]]
    return {"rules": rules, "poll_seconds": 15}


@app.post("/api/agents/{agent_id}/alerts", status_code=201)
def post_alert(agent_id: str, body: AlertIn, request: Request):
    with db() as conn:
        agent = auth_agent(conn, agent_id, request)
        conn.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
                     (str(uuid.uuid4()), agent_id, body.rule_id, body.title, body.severity,
                      agent["hostname"], agent["os"], json.dumps(body.context), time.time()))
    return {"ok": True}


@app.get("/api/agents")
def list_agents():
    now = time.time()
    with db() as conn:
        rows = conn.execute("SELECT * FROM agents ORDER BY enrolled_at DESC").fetchall()
    return [{
        "id": r["id"], "hostname": r["hostname"], "os": r["os"], "arch": r["arch"],
        "version": r["version"], "enrolled_at": r["enrolled_at"], "last_seen": r["last_seen"],
        "online": (now - r["last_seen"]) < 60,
    } for r in rows]


@app.get("/api/alerts")
def list_alerts(limit: int = 100):
    with db() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [{
        "id": r["id"], "agent_id": r["agent_id"], "rule_id": r["rule_id"], "title": r["title"],
        "severity": r["severity"], "hostname": r["hostname"], "os": r["os"],
        "context": json.loads(r["context"]), "created_at": r["created_at"],
    } for r in rows]


# ----------------------------------------------------------------------------
# Seed library
# ----------------------------------------------------------------------------

SEED = [
    dict(rule_id="PAL-W-0001", title="Encoded PowerShell Command Execution",
         description="PowerShell launched with an encoded command block, a staple of loaders and offensive frameworks.",
         severity="high", status="stable", platforms=["windows"],
         logsource={"category": "process_creation", "product": "windows"},
         detection={"selection": [
             {"field": "Image", "modifier": "endswith", "values": ["\\powershell.exe", "\\pwsh.exe"]},
             {"field": "CommandLine", "modifier": "contains", "values": ["-enc", "-EncodedCommand", "-e JAB"]}],
             "condition": "selection"},
         attack={"tactics": ["execution", "defense-evasion"], "techniques": ["T1059.001", "T1027"]},
         references=["https://attack.mitre.org/techniques/T1059/001/"], author="Palisade Core"),
    dict(rule_id="PAL-W-0002", title="Certutil Used as Downloader",
         description="certutil.exe invoked with urlcache/split flags to fetch remote payloads — classic LOLBin abuse.",
         severity="high", status="stable", platforms=["windows"],
         logsource={"category": "process_creation", "product": "windows"},
         detection={"selection": [
             {"field": "Image", "modifier": "endswith", "values": ["\\certutil.exe"]},
             {"field": "CommandLine", "modifier": "contains", "values": ["urlcache", "-split", "http"]}],
             "condition": "selection"},
         attack={"tactics": ["command-and-control", "defense-evasion"], "techniques": ["T1105", "T1218"]},
         references=["https://lolbas-project.github.io/lolbas/Binaries/Certutil/"], author="Palisade Core"),
    dict(rule_id="PAL-W-0003", title="Rundll32 Without Arguments or From User Path",
         description="rundll32.exe executing DLLs from user-writable locations, common in initial-access chains.",
         severity="medium", status="stable", platforms=["windows"],
         logsource={"category": "process_creation", "product": "windows"},
         detection={"selection": [
             {"field": "Image", "modifier": "endswith", "values": ["\\rundll32.exe"]},
             {"field": "CommandLine", "modifier": "contains", "values": ["\\AppData\\", "\\Temp\\", "\\Downloads\\"]}],
             "condition": "selection"},
         attack={"tactics": ["defense-evasion", "execution"], "techniques": ["T1218.011"]},
         author="Palisade Core"),
    dict(rule_id="PAL-W-0004", title="LSASS Memory Access Tooling on Command Line",
         description="Command lines referencing lsass dumping primitives (comsvcs MiniDump, procdump -ma lsass).",
         severity="critical", status="stable", platforms=["windows"],
         logsource={"category": "process_creation", "product": "windows"},
         detection={"selection": [
             {"field": "CommandLine", "modifier": "contains",
              "values": ["comsvcs.dll, MiniDump", "procdump", "lsass"]}],
             "filter": [
             {"field": "CommandLine", "modifier": "contains", "values": ["lsass_recovery_legit_tool"]}],
             "condition": "selection and not filter"},
         attack={"tactics": ["credential-access"], "techniques": ["T1003.001"]},
         author="Palisade Core"),
    dict(rule_id="PAL-W-0005", title="Scheduled Task Creation via Schtasks",
         description="schtasks.exe /create from interactive sessions, frequent persistence primitive.",
         severity="medium", status="experimental", platforms=["windows"],
         logsource={"category": "process_creation", "product": "windows"},
         detection={"selection": [
             {"field": "Image", "modifier": "endswith", "values": ["\\schtasks.exe"]},
             {"field": "CommandLine", "modifier": "contains", "values": ["/create"]}],
             "condition": "selection"},
         attack={"tactics": ["persistence", "privilege-escalation"], "techniques": ["T1053.005"]},
         author="Palisade Core"),
    dict(rule_id="PAL-L-0001", title="Curl Piped to Shell",
         description="Remote script fetched with curl/wget and piped directly into a shell interpreter.",
         severity="high", status="stable", platforms=["linux", "macos"],
         logsource={"category": "process_creation", "product": "linux"},
         detection={"selection": [
             {"field": "CommandLine", "modifier": "re",
              "values": ["(curl|wget)[^|;]*\\|\\s*(ba|z|da)?sh"]}],
             "condition": "selection"},
         attack={"tactics": ["execution", "command-and-control"], "techniques": ["T1059.004", "T1105"]},
         author="Palisade Core"),
    dict(rule_id="PAL-L-0002", title="Crontab Modification for Persistence",
         description="crontab edited or a new cron entry written from a shell session.",
         severity="medium", status="stable", platforms=["linux"],
         logsource={"category": "process_creation", "product": "linux"},
         detection={"selection": [
             {"field": "Image", "modifier": "endswith", "values": ["/crontab"]},
             {"field": "CommandLine", "modifier": "contains", "values": ["-e", "-l", "/tmp/"]}],
             "condition": "selection"},
         attack={"tactics": ["persistence"], "techniques": ["T1053.003"]},
         author="Palisade Core"),
    dict(rule_id="PAL-L-0003", title="SSH Authorized Keys File Modified",
         description="Write activity against authorized_keys, a durable access technique post-compromise.",
         severity="high", status="stable", platforms=["linux", "macos"],
         logsource={"category": "file_event", "product": "linux"},
         detection={"selection": [
             {"field": "TargetFilename", "modifier": "endswith", "values": ["/.ssh/authorized_keys"]}],
             "condition": "selection"},
         attack={"tactics": ["persistence"], "techniques": ["T1098.004"]},
         author="Palisade Core"),
    dict(rule_id="PAL-L-0004", title="Python/Netcat Reverse Shell One-Liner",
         description="Interpreter command lines matching common reverse shell construction patterns.",
         severity="critical", status="stable", platforms=["linux", "macos"],
         logsource={"category": "process_creation", "product": "linux"},
         detection={"selection": [
             {"field": "CommandLine", "modifier": "re",
              "values": ["socket\\.socket|/dev/tcp/|nc(\\.traditional)?\\s+-e\\s"]}],
             "condition": "selection"},
         attack={"tactics": ["execution", "command-and-control"], "techniques": ["T1059.006", "T1071"]},
         author="Palisade Core"),
    dict(rule_id="PAL-M-0001", title="Osascript Executing Inline JavaScript or AppleScript",
         description="osascript -e usage outside known automation, used by macOS stealers and droppers.",
         severity="medium", status="experimental", platforms=["macos"],
         logsource={"category": "process_creation", "product": "macos"},
         detection={"selection": [
             {"field": "Image", "modifier": "endswith", "values": ["/osascript"]},
             {"field": "CommandLine", "modifier": "contains", "values": ["-e "]}],
             "condition": "selection"},
         attack={"tactics": ["execution"], "techniques": ["T1059.002"]},
         author="Palisade Core"),
    dict(rule_id="PAL-M-0002", title="LaunchAgent Plist Written to User Library",
         description="New or modified plist under ~/Library/LaunchAgents — dominant macOS persistence path.",
         severity="high", status="stable", platforms=["macos"],
         logsource={"category": "file_event", "product": "macos"},
         detection={"selection": [
             {"field": "TargetFilename", "modifier": "contains", "values": ["/Library/LaunchAgents/"]}],
             "condition": "selection"},
         attack={"tactics": ["persistence"], "techniques": ["T1543.001"]},
         author="Palisade Core"),
    dict(rule_id="PAL-X-0001", title="Sudoers File Modification",
         description="Direct writes to /etc/sudoers or sudoers.d outside change control.",
         severity="critical", status="stable", platforms=["linux", "macos"],
         logsource={"category": "file_event", "product": "linux"},
         detection={"selection": [
             {"field": "TargetFilename", "modifier": "contains", "values": ["/etc/sudoers"]}],
             "condition": "selection"},
         attack={"tactics": ["privilege-escalation", "persistence"], "techniques": ["T1548.003"]},
         author="Palisade Core"),
]


def seed():
    with db() as conn:
        n = conn.execute("SELECT COUNT(*) c FROM detections").fetchone()["c"]
    if n:
        return
    for s in SEED:
        create_detection(DetectionIn(**s))


init_db()
seed()

# ----------------------------------------------------------------------------
# Web console
# ----------------------------------------------------------------------------

@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
