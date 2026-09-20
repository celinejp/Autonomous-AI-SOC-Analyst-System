#!/usr/bin/env python3
"""Evaluate the deterministic detection layer (ingest + ATT&CK rules + signatures, no LLM) on
real, publicly available attack telemetry instead of hand-written logs.

Datasets (downloaded on first run into backend/data/public/, which is git-ignored):
  * Splunk attack_data  https://github.com/splunk/attack_data  - real Atomic Red Team captures,
    one folder per ATT&CK technique ID. Label = technique ID -> per-rule recall.
  * EVTX-ATTACK-SAMPLES https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES - real Windows/Sysmon
    events, labeled by ATT&CK tactic. Label = tactic -> per-tactic detection rate.

Both are attack captures, so this measures RECALL only. Most events in these files are ordinary
background activity, and the datasets carry no per-event labels, so precision / false-positive
rate cannot be measured from them.

With --llm the full detection agent (rules + LLM) also runs on the small samples (<= 300 events; a whole
capture is too large for a prompt), including real EVTX samples the rules missed, to show what the LLM adds.

Usage: python scripts/eval_public_datasets.py [--splunk-only | --evtx-only] [--llm] [--max-mb 40]
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import re
import subprocess
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
csv.field_size_limit(10 ** 8)

from app.agents.detection_agent import detect_rules_only, detection_agent  # noqa: E402
from app.agents.ingest_agent import ingest_agent  # noqa: E402
from app.agents.windows_events import TEXT_EVENT_START_RE  # noqa: E402
from app.detection.attack_rules import ATTACK_DETECTION_RULES  # noqa: E402

CACHE = ROOT / "data" / "public"
RESULTS = ROOT / "tests" / "results" / "public_datasets_report.json"
SPLUNK_REPO = "https://github.com/splunk/attack_data"
SPLUNK_MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
EVTX_CSV = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/evtx_data.csv"
CHUNK = 5000  # the app's per-submission line limit
PREFERRED = ("sysmon", "security", "powershell", "windows")


def download(url: str, dest: Path, max_bytes: Optional[int] = None) -> bool:
    if dest.exists() and dest.stat().st_size > 0:
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=120) as resp, open(dest, "wb") as out:
            written = 0
            while chunk := resp.read(1 << 20):
                out.write(chunk)
                written += len(chunk)
                if max_bytes and written > max_bytes:
                    break
        return True
    except Exception as e:  # network/404: report and continue
        print(f"  download failed {url}: {e}")
        dest.unlink(missing_ok=True)
        return False


async def alerts_for(lines: List[str]) -> Tuple[int, List]:
    """Ingest + deterministic detection, in production-sized chunks. Returns (parsed_events, alerts)."""
    parsed, alerts = 0, []
    for i in range(0, len(lines), CHUNK):
        state = await ingest_agent({"raw_logs": lines[i:i + CHUNK], "logs": [], "alerts": [], "agent_execution_log": []})
        parsed += len(state["logs"])
        alerts.extend(detect_rules_only(state["logs"]))
    return parsed, alerts


LLM_MAX_EVENTS = 300


async def full_detection(lines: List[str]) -> List:
    """Ingest + the full detection agent (LLM + rules) on one small sample."""
    state = await ingest_agent({"raw_logs": lines, "logs": [], "alerts": [], "agent_execution_log": []})
    state = await detection_agent(state)
    return state["alerts"]


def is_llm_alert(alert) -> bool:
    rule = alert.detection_rule or ""
    return not (rule.startswith("ATT&CK Rule") or rule.startswith("rule:") or rule in ("multiple_failed_logins", "port_scanning"))


def rule_ids(alerts) -> set:
    return {a.detection_rule.split(": ", 1)[1] for a in alerts if a.detection_rule.startswith("ATT&CK Rule: ")}


def family(tid: str) -> str:
    return tid.split(".")[0]


# ---------------------------------------------------------------- Splunk attack_data
def split_events(text: str) -> List[str]:
    """One event per string: one per line normally, but Splunk's WinEventLog files use multi-line
    blocks that each start with a 'MM/DD/YYYY HH:MM:SS AM' line."""
    lines = text.splitlines()
    if lines and TEXT_EVENT_START_RE.match(lines[0]):
        events, current = [], []
        for line in lines:
            if TEXT_EVENT_START_RE.match(line) and current:
                events.append("\n".join(current))
                current = []
            current.append(line)
        if current:
            events.append("\n".join(current))
        return events
    return [l for l in lines if l.strip()]


def prepare_splunk() -> Optional[Path]:
    repo = CACHE / "attack_data"
    if not repo.exists():
        print("cloning splunk/attack_data (metadata only, no data files)...")
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", SPLUNK_REPO, str(repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "sparse-checkout", "set", "datasets/attack_techniques"], check=True, capture_output=True)
    return repo


def pointer_size(path: Path) -> int:
    m = re.search(r"size (\d+)", path.read_text(errors="ignore")[:300])
    return int(m.group(1)) if m else 10 ** 12


def pick_files(repo: Path, tid: str, max_bytes: int, per_technique: int) -> List[Path]:
    folder = repo / "datasets" / "attack_techniques" / tid
    if not folder.exists():
        return []
    candidates = [p for p in folder.rglob("*.log") if pointer_size(p) <= max_bytes]
    candidates.sort(key=lambda p: (not any(k in p.name.lower() for k in PREFERRED), pointer_size(p)))
    return candidates[:per_technique]


async def eval_splunk(max_mb: int, per_technique: int, use_llm: bool) -> Dict:
    repo = prepare_splunk()
    out = {}
    for tid in ATTACK_DETECTION_RULES:
        files = pick_files(repo, tid, max_mb << 20, per_technique)
        if not files:
            out[tid] = {"status": "no dataset in repo"}
            continue
        results = []
        for f in files:
            rel = f.relative_to(repo).as_posix()
            local = CACHE / "splunk" / rel
            if not download(SPLUNK_MEDIA + rel, local):
                continue
            lines = split_events(local.read_text(errors="ignore"))
            parsed, alerts = await alerts_for(lines)
            ids = rule_ids(alerts)
            hit_fam = any(family(t) == family(tid) for a in alerts for t in a.mitre_techniques)
            llm = None
            if use_llm and len(lines) <= LLM_MAX_EVENTS and not any(r.get("llm") for r in results):
                found = await full_detection(lines)
                llm_alerts = [a for a in found if is_llm_alert(a)]
                llm = {"llm_alerts": len(llm_alerts), "llm_names_family": any(family(t) == family(tid) for a in llm_alerts for t in a.mitre_techniques),
                       "any_alert": bool(found)}
                print(f"    LLM+rules on {f.name[:40]}: any alert={bool(found)} llm alerts={len(llm_alerts)} names family={llm['llm_names_family']}")
            results.append({"file": f.name, "llm": llm, "lines": len(lines), "parsed": parsed, "target_rule_fired": tid in ids,
                            "family_alert": tid in ids or hit_fam, "any_alert": bool(alerts),
                            "other_rules_fired": sorted(ids - {tid})})
            print(f"  {tid:10s} {f.name[:42]:42s} lines={len(lines):6d} parsed={parsed:6d} "
                  f"rule={'HIT ' if tid in ids else 'miss'} family={'HIT ' if (tid in ids or hit_fam) else 'miss'}")
        out[tid] = {"status": "ok", "samples": results} if results else {"status": "download failed"}
    return out


# ---------------------------------------------------------------- EVTX-ATTACK-SAMPLES
def csv_rows_to_events(path: Path) -> Dict[Tuple[str, str], List[str]]:
    """Group the pre-parsed evtx_data.csv rows by (tactic, file) as JSON event lines."""
    files: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    with open(path, newline="", errors="ignore") as f:
        for row in csv.DictReader(f):
            event = {k: v for k, v in row.items() if v not in ("", "-", None) and k and not k.startswith("{")}
            files[(row.get("EVTX_Tactic", "?"), row.get("EVTX_FileName", "?"))].append(json.dumps(event))
    return files


async def eval_evtx(use_llm: bool, llm_samples: int) -> Dict:
    local = CACHE / "evtx_data.csv"
    if not download(EVTX_CSV, local):
        return {}
    files = csv_rows_to_events(local)
    rule_tactic = {tid: r["tactic"] for tid, r in ATTACK_DETECTION_RULES.items()}
    by_tactic: Dict[str, Dict] = defaultdict(lambda: {"samples": 0, "any_alert": 0, "tactic_rule": 0, "files_missed": []})
    missed_small: List[Tuple[str, str, List[str]]] = []
    for (tactic, name), lines in sorted(files.items()):
        parsed, alerts = await alerts_for(lines)
        rules = rule_ids(alerts)
        stats = by_tactic[tactic]
        stats["samples"] += 1
        stats["any_alert"] += bool(alerts)
        matched = any(rule_tactic[t] == tactic for t in rules)
        stats["tactic_rule"] += matched
        if not alerts:
            stats["files_missed"].append(name)
            if len(lines) <= LLM_MAX_EVENTS:
                missed_small.append((tactic, name, lines))
    if use_llm and missed_small:
        step = max(1, len(missed_small) // llm_samples)
        chosen = missed_small[::step][:llm_samples]
        caught = 0
        print(f"\n  LLM on {len(chosen)} real EVTX samples the rules missed (attacks outside the 24 rules):")
        for tactic, name, lines in chosen:
            found = await full_detection(lines)
            caught += bool(found)
            print(f"    {tactic:20s} {name[:44]:44s} -> {'alert' if found else 'no alert'}")
        by_tactic["_llm_on_rule_misses"] = {"samples": len(chosen), "alert_raised": caught}
    return by_tactic


# ---------------------------------------------------------------- report
async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--splunk-only", action="store_true")
    ap.add_argument("--evtx-only", action="store_true")
    ap.add_argument("--llm", action="store_true", help="also run the LLM detection on small samples (needs Ollama)")
    ap.add_argument("--llm-evtx", type=int, default=20, help="EVTX rule-misses to run through the LLM")
    ap.add_argument("--max-mb", type=int, default=40, help="skip Splunk data files larger than this")
    ap.add_argument("--per-technique", type=int, default=4, help="Splunk files sampled per technique")
    args = ap.parse_args()
    report: Dict = {}

    if not args.evtx_only:
        print("\n== Splunk attack_data (per ATT&CK rule) ==")
        report["splunk_attack_data"] = await eval_splunk(args.max_mb, args.per_technique, args.llm)
        s = report["splunk_attack_data"]
        with_data = {t: v for t, v in s.items() if v.get("status") == "ok"}
        hit = [t for t, v in with_data.items() if any(x["target_rule_fired"] for x in v["samples"])]
        fam = [t for t, v in with_data.items() if any(x["family_alert"] for x in v["samples"])]
        print(f"\nrules with a public dataset: {len(with_data)}/24 | target rule fired: {len(hit)} | "
              f"any alert in the technique family: {len(fam)}")
        llm_rows = [x["llm"] for v in with_data.values() for x in v["samples"] if x.get("llm")]
        if llm_rows:
            print(f"LLM+rules on {len(llm_rows)} small real captures: any alert {sum(r['any_alert'] for r in llm_rows)}, "
                  f"LLM itself named the technique family {sum(r['llm_names_family'] for r in llm_rows)}")
        print("no dataset:", sorted(t for t, v in s.items() if v.get("status") != "ok"))
        print("rule missed:", sorted(set(with_data) - set(hit)))

    if not args.splunk_only:
        print("\n== EVTX-ATTACK-SAMPLES (per tactic) ==")
        report["evtx_attack_samples"] = await eval_evtx(args.llm, args.llm_evtx)
        rows = [x for k, x in report["evtx_attack_samples"].items() if not k.startswith("_")]
        total, anyhit = sum(v["samples"] for v in rows), sum(v["any_alert"] for v in rows)
        for tactic, v in sorted((k, x) for k, x in report["evtx_attack_samples"].items() if not k.startswith("_")):
            print(f"  {tactic:22s} samples={v['samples']:3d} any-alert={v['any_alert']:3d} matching-tactic-rule={v['tactic_rule']:3d}")
        print(f"\nEVTX samples: {total} | alert raised on {anyhit} ({anyhit / max(total, 1):.0%})")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(report, indent=1))
    print("wrote", RESULTS)


if __name__ == "__main__":
    asyncio.run(main())
