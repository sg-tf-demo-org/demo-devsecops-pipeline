#!/usr/bin/env python3
"""Start DevSecOps demo chat sessions on devops-pipeline-engineer; write watch URLs.

Requires: AIDEN_GUILD_TOKEN
Optional: DEVSECOPS_SMOKE_OUT (default /tmp/devsecops-smoke-results.json)
          DEVSECOPS_SMOKE_BEATS=d1,d2,d3,d4 (subset)
          DEVSECOPS_SMOKE_MAX_WAIT=180 DEVSECOPS_SMOKE_POLL=10
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ORG = os.environ.get("AIDEN_ORG_ID", "aee77bee-6885-4b4b-b9c0-e0c7ae81be96")
BASE = (
    os.environ.get("AIDEN_GUILD_URL")
    or os.environ.get("AIDEN_GUILD_BASE")
    or "https://stage.dev.stackgen.com"
).rstrip("/")
TOKEN = (
    os.environ.get("AIDEN_GUILD_TOKEN")
    or os.environ.get("GUILD_TOKEN")
    or os.environ.get("STACKGEN_TOKEN")
)
AGENT = "devops-pipeline-engineer"
OUT = Path(os.environ.get("DEVSECOPS_SMOKE_OUT", "/tmp/devsecops-smoke-results.json"))
MAX_WAIT = int(os.environ.get("DEVSECOPS_SMOKE_MAX_WAIT", "180"))
POLL = int(os.environ.get("DEVSECOPS_SMOKE_POLL", "10"))
WANT = {
    x.strip().lower()
    for x in os.environ.get("DEVSECOPS_SMOKE_BEATS", "d1,d2,d3,d4").split(",")
    if x.strip()
}

PROMPTS = [
    (
        "d1",
        "Use persona devops-pipeline-engineer. Load skills explain-devsecops-gate and remediate-devsecops-findings. "
        "Explain the DevSecOps harness story in 5 bullets (Gitleaks→Semgrep→Trivy→cosign CI→Kyverno ns devsecops-demo). "
        "Then describe how you would deliberately open a PR with fixtures/vulnerable/config.py so Gitleaks fails, "
        "and what the remediating compliant/config.py change would be. Do not call create_agent. Do not touch otel-demo.",
    ),
    (
        "d2",
        "Use persona devops-pipeline-engineer. Load skill explain-devsecops-gate. "
        "Semgrep failed on fixtures/vulnerable/sql_helper.py (SQL string concat + pickle.loads). "
        "Name the gate, quote the offending patterns, and describe the compliant/sql_helper.py fix. "
        "Do not silently claim CI is green.",
    ),
    (
        "d3",
        "Use persona devops-pipeline-engineer. Load skills explain-devsecops-gate and remediate-devsecops-findings. "
        "Trivy fs flagged urllib3==1.26.5 (e.g. CVE-2021-33503) and Trivy image would fail on python:3.8.0-slim. "
        "Explain the gate, then describe remediating with fixtures/compliant requirements + python:3.12-slim, "
        "and that cosign sign+verify in CI is the v1 trust anchor (not cluster signature enforcement).",
    ),
    (
        "d4",
        "Use persona devops-pipeline-engineer. Load skills explain-devsecops-gate and remediate-devsecops-findings. "
        "A Pod apply in namespace devsecops-demo was denied by Kyverno (privileged, no limits, image :latest). "
        "Explain which policies fired and describe the remediating fixtures/compliant/good-pod.yaml. "
        "Never apply to otel-demo or cluster-wide.",
    ),
]


def guild(method, path, body=None, timeout=180):
    sep = "&" if "?" in path else "?"
    url = BASE + path + sep + urllib.parse.urlencode({"orgId": ORG})
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "x-org-id": ORG,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw) if raw else {}
        except Exception:
            return e.code, {"raw": raw[:4000]}


def watch_url(sid: str) -> str:
    enc = urllib.parse.quote(f"session:{sid}", safe="")
    return f"{BASE}/app/settings/workspace/devops-copilot/executions/{enc}/watch"


def start_chat(message: str) -> str:
    code, data = guild(
        "POST",
        f"/guild/api/v1/agents/{AGENT}/chat/start",
        {"message": message},
        timeout=180,
    )
    if code not in (200, 201, 202):
        raise RuntimeError(f"chat/start {code}: {data}")
    sid = data.get("session_id") or data.get("id")
    if not sid:
        raise RuntimeError(f"no session_id: {data}")
    return sid


def poll(sid: str) -> dict:
    deadline = time.time() + MAX_WAIT
    last: dict = {}
    while time.time() < deadline:
        code, sess = guild("GET", f"/guild/api/v1/sessions/{sid}")
        code2, ex = guild("GET", f"/guild/api/v1/executions/session%3A{sid}")
        status = None
        if isinstance(ex, dict):
            status = (ex.get("execution") or {}).get("status") or ex.get("status")
        if isinstance(sess, dict) and not status:
            status = sess.get("status")
        last = {
            "session_id": sid,
            "status": status,
            "watch": watch_url(sid),
            "agent": (sess or {}).get("agent_name") if isinstance(sess, dict) else None,
            "http_session": code,
            "http_execution": code2,
        }
        if status in ("completed", "failed", "error", "cancelled"):
            return last
        time.sleep(POLL)
    last["status"] = last.get("status") or "timeout"
    return last


def main() -> int:
    if not TOKEN:
        print("AIDEN_GUILD_TOKEN required", flush=True)
        return 1
    if "lcs.cloud.stackgen.com" in BASE:
        print("Refusing LCS base", flush=True)
        return 1

    # Verify agent exists
    c, ag = guild("GET", f"/guild/api/v1/agents/{AGENT}")
    if c != 200:
        print(f"Agent {AGENT} missing (HTTP {c}). Run register_devops_pipeline_engineer_aiden.py first.", flush=True)
        return 1
    print(f"agent ok integrations={ag.get('integrations')} runners={ag.get('remote_runners')}", flush=True)

    results = []
    for beat, msg in PROMPTS:
        if beat not in WANT:
            continue
        print(f"==> starting {beat}", flush=True)
        try:
            sid = start_chat(msg)
            print(f"    session={sid}", flush=True)
            print(f"    watch={watch_url(sid)}", flush=True)
            row = poll(sid)
            row["beat"] = beat
            row["prompt_preview"] = msg[:120]
            results.append(row)
            print(f"    status={row.get('status')}", flush=True)
        except Exception as e:
            results.append({"beat": beat, "error": str(e), "watch": None})
            print(f"    ERROR {e}", flush=True)

    OUT.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {OUT}", flush=True)
    print("\n## Watch links\n", flush=True)
    for r in results:
        print(f"- **{r.get('beat')}**: {r.get('watch') or r.get('error')}", flush=True)
    return 0 if all(r.get("watch") for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
