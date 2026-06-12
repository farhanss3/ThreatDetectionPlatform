#!/usr/bin/env python3
"""
PALISADE agent — cross-platform endpoint sensor (Windows / Linux / macOS).

Enrolls with a Palisade server, pulls enabled detections for its platform,
evaluates them against local telemetry (process creation snapshots via psutil,
plus lightweight file-integrity watch for file_event rules), and reports alerts.

Usage:
  python3 palisade_agent.py --server http://127.0.0.1:8787            # run forever
  python3 palisade_agent.py --server http://127.0.0.1:8787 --once     # single scan (testing)

State (agent id/key, file baselines) is stored next to the script in
palisade_agent_state.json, or at --state PATH.
"""
import argparse
import fnmatch
import json
import os
import platform
import re
import socket
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

try:
    import psutil
except ImportError:
    print("palisade-agent: psutil is required -> pip install psutil", file=sys.stderr)
    sys.exit(1)

OS_NAME = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system(), "linux")


# ----------------------------------------------------------------------------
# Server client
# ----------------------------------------------------------------------------

class Client:
    def __init__(self, server: str, state_path: Path):
        self.server = server.rstrip("/")
        self.state_path = state_path
        self.state = self._load_state()

    def _load_state(self):
        if self.state_path.exists():
            return json.loads(self.state_path.read_text())
        return {}

    def _save_state(self):
        self.state_path.write_text(json.dumps(self.state, indent=2))

    def _req(self, method, path, body=None, auth=True):
        url = self.server + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if auth:
            req.add_header("X-Palisade-Key", self.state.get("key", ""))
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode() or "{}")

    def enroll(self):
        if self.state.get("agent_id"):
            # validate existing creds; re-enroll if the server no longer knows us
            try:
                self.heartbeat()
                return
            except urllib.error.HTTPError as e:
                if e.code != 401:
                    return
                log("stored credentials rejected, re-enrolling")
                self.state.pop("agent_id", None)
                self.state.pop("key", None)
        body = {"hostname": socket.gethostname(), "os": OS_NAME,
                "arch": platform.machine(), "version": "0.1.0"}
        out = self._req("POST", "/api/agents/enroll", body, auth=False)
        self.state["agent_id"] = out["agent_id"]
        self.state["key"] = out["key"]
        self._save_state()
        log(f"enrolled as {out['agent_id']}")

    def heartbeat(self):
        self._req("POST", f"/api/agents/{self.state['agent_id']}/heartbeat", {})

    def tasking(self):
        return self._req("GET", f"/api/agents/{self.state['agent_id']}/tasking")

    def alert(self, rule, context):
        self._req("POST", f"/api/agents/{self.state['agent_id']}/alerts", {
            "rule_id": rule["rule_id"], "title": rule["title"],
            "severity": rule["severity"], "context": context,
        })


def log(msg):
    print(f"[palisade-agent] {time.strftime('%H:%M:%S')} {msg}", flush=True)


# ----------------------------------------------------------------------------
# Rule evaluation
# ----------------------------------------------------------------------------

def norm(s):
    return (s or "").lower()


def match_item(item, fields) -> bool:
    """fields: dict of canonical field -> string value from telemetry."""
    val = norm(fields.get(item["field"], ""))
    mod = item.get("modifier", "equals")
    for raw in item["values"]:
        v = norm(raw)
        if mod == "contains" and v in val:
            return True
        if mod == "endswith" and val.endswith(v):
            return True
        if mod == "startswith" and val.startswith(v):
            return True
        if mod == "equals" and val == v:
            return True
        if mod == "re" and re.search(raw, fields.get(item["field"], ""), re.I):
            return True
    return False


def eval_rule(rule, fields) -> bool:
    d = rule["detection"]
    sel = all(match_item(i, fields) for i in d.get("selection", []))
    if not sel:
        return False
    cond = d.get("condition", "selection")
    if "not filter" in cond and d.get("filter"):
        if all(match_item(i, fields) for i in d["filter"]):
            return False
    return True


# ----------------------------------------------------------------------------
# Telemetry collectors
# ----------------------------------------------------------------------------

class ProcessScanner:
    """Snapshot-based process-creation approximation: evaluates processes the
    first time they are seen. Production agents use ETW / eBPF / ES framework;
    this keeps the agent dependency-light and fully cross-platform."""

    def __init__(self):
        self.seen = {}  # pid -> create_time

    def new_processes(self):
        current = {}
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "ppid", "create_time"]):
            try:
                info = p.info
                key = (info["pid"], info.get("create_time"))
                current[key] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        fresh = [v for k, v in current.items() if k not in self.seen]
        self.seen = current
        return fresh

    @staticmethod
    def to_fields(info):
        parent_exe = ""
        try:
            parent = psutil.Process(info["ppid"]) if info.get("ppid") else None
            parent_exe = parent.exe() if parent else ""
        except Exception:
            pass
        return {
            "Image": info.get("exe") or info.get("name") or "",
            "CommandLine": " ".join(info.get("cmdline") or []),
            "ParentImage": parent_exe,
            "User": info.get("username") or "",
        }


class FileWatcher:
    """mtime-baseline watcher for file_event rules. Watch paths are derived from
    rule selection values (endswith/contains on TargetFilename)."""

    CANDIDATE_DIRS = {
        "linux": ["/etc", str(Path.home() / ".ssh")],
        "macos": ["/etc", str(Path.home() / ".ssh"), str(Path.home() / "Library/LaunchAgents")],
        "windows": [],
    }

    def __init__(self, state):
        self.baseline = state.setdefault("file_baseline", {})

    def watchlist(self, rules):
        pats = []
        for r in rules:
            if r["logsource"].get("category") != "file_event":
                continue
            for item in r["detection"].get("selection", []):
                if item["field"] == "TargetFilename":
                    for v in item["values"]:
                        pats.append((r, item.get("modifier", "contains"), v))
        return pats

    def changed_files(self, rules):
        hits = []
        pats = self.watchlist(rules)
        if not pats:
            return hits
        for d in self.CANDIDATE_DIRS.get(OS_NAME, []):
            root = Path(d)
            if not root.exists():
                continue
            try:
                paths = [p for p in root.rglob("*") if p.is_file()]
            except PermissionError:
                continue
            for p in paths:
                try:
                    m = p.stat().st_mtime
                except OSError:
                    continue
                sp = str(p)
                old = self.baseline.get(sp)
                self.baseline[sp] = m
                if old is None or old == m:
                    continue  # first sight = baseline; unchanged = ignore
                for rule, mod, v in pats:
                    target = sp.lower()
                    vv = v.lower()
                    if (mod == "endswith" and target.endswith(vv)) or \
                       (mod == "contains" and vv in target) or \
                       (mod == "equals" and target == vv):
                        hits.append((rule, {"TargetFilename": sp}))
        return hits


# ----------------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------------

def run(server, state_path, once=False):
    client = Client(server, state_path)
    client.enroll()
    scanner = ProcessScanner()
    watcher = FileWatcher(client.state)
    scanner.new_processes()  # prime baseline so we only judge new activity
    dedupe = {}
    rules, poll = [], 15
    last_task = 0

    while True:
        try:
            client.heartbeat()
            if time.time() - last_task > 30 or not rules:
                t = client.tasking()
                rules, poll = t["rules"], t.get("poll_seconds", 15)
                last_task = time.time()
                log(f"tasking: {len(rules)} rules for platform '{OS_NAME}'")

            proc_rules = [r for r in rules if r["logsource"].get("category") == "process_creation"]
            for info in scanner.new_processes():
                fields = ProcessScanner.to_fields(info)
                for rule in proc_rules:
                    if eval_rule(rule, fields):
                        key = (rule["rule_id"], fields["Image"], fields["CommandLine"])
                        if time.time() - dedupe.get(key, 0) < 300:
                            continue
                        dedupe[key] = time.time()
                        log(f"ALERT {rule['rule_id']} {rule['title']} :: {fields['CommandLine'][:120]}")
                        client.alert(rule, fields)

            for rule, ctx in watcher.changed_files(rules):
                key = (rule["rule_id"], ctx["TargetFilename"])
                if time.time() - dedupe.get(key, 0) < 300:
                    continue
                dedupe[key] = time.time()
                log(f"ALERT {rule['rule_id']} {rule['title']} :: {ctx['TargetFilename']}")
                client.alert(rule, ctx)

            client._save_state()
        except urllib.error.URLError as e:
            log(f"server unreachable: {e}")
        except Exception as e:
            log(f"error: {e}")

        if once:
            return
        time.sleep(min(poll, 15))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="Palisade server URL")
    ap.add_argument("--state", default=str(Path(__file__).with_name("palisade_agent_state.json")))
    ap.add_argument("--once", action="store_true", help="single scan cycle, then exit")
    args = ap.parse_args()
    run(args.server, Path(args.state), once=args.once)
