#!/usr/bin/env python3
"""DevSecOps demo: per-gate violation explain + remediating fix sessions.

Starts chat/start on devops-pipeline-engineer for each OSS gate:
  - *_violation: agent identifies what failed in the pipeline
  - *_fix: agent raises / describes the compliant remediating change

Requires: AIDEN_GUILD_TOKEN
Writes: DEVSECOPS_SMOKE_OUT (default /tmp/devsecops-gate-watch-links.json)
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
OUT = Path(
    os.environ.get(
        "DEVSECOPS_SMOKE_OUT",
        str(Path(__file__).resolve().parent / "gate-watch-links.json"),
    )
)
MAX_WAIT = int(os.environ.get("DEVSECOPS_SMOKE_MAX_WAIT", "180"))
POLL = int(os.environ.get("DEVSECOPS_SMOKE_POLL", "8"))
WANT = {
    x.strip().lower()
    for x in os.environ.get(
        "DEVSECOPS_SMOKE_BEATS",
        "pipeline,gitleaks_v,gitleaks_f,semgrep_v,semgrep_f,trivy_v,trivy_f,cosign_v,cosign_f,kyverno_v,kyverno_f",
    ).split(",")
    if x.strip()
}

# (id, title, message)
PROMPTS = [
    (
        "pipeline",
        "Pipeline setup (OSS gates)",
        """Use persona devops-pipeline-engineer. Load skills explain-devsecops-gate and remediate-devsecops-findings.

Explain how to SET UP and MANAGE a DevSecOps pipeline with these open-source guardrails in place (use the pack under devsecops-demo/):

1. Pre-commit / PR: Gitleaks — secrets never reach history
2. PR SAST: Semgrep — injection / unsafe deserialization / auth issues
3. PR deps: Trivy fs — HIGH/CRITICAL dependency CVEs block merge
4. Container build: Trivy image blocks HIGH/CRITICAL; cosign sign + verify in CI is the trust anchor (v1: CI only, not cluster)
5. Admission: Kyverno Policies only in namespace devsecops-demo — deny privileged, require CPU/memory limits, deny :latest

For each gate: name the workflow/policy file path in the pack, what "green" means, and what Aiden does when red (explain → remediate).
Do not call create_agent. Do not touch otel-demo or edit other personas.""",
    ),
    (
        "gitleaks_v",
        "Gitleaks — violation found",
        """Use persona devops-pipeline-engineer. Load skill explain-devsecops-gate.

A PR (or proposed change) includes fixtures/vulnerable/config.py with hardcoded AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and a fake ghp_ token. The Gitleaks job / pre-commit hook FAILED.

Figure out the problem: name the gate (Gitleaks), quote the violating patterns, explain why this must block merge, and what check the developer sees. Do NOT remediate yet — diagnosis only. STOP after the diagnosis.""",
    ),
    (
        "gitleaks_f",
        "Gitleaks — fix raised",
        """Use persona devops-pipeline-engineer. Load skill remediate-devsecops-findings.

Gitleaks already failed on fixtures/vulnerable/config.py (hardcoded AKIA… / ghp_ demo secrets). Raise the FIX: replace with fixtures/compliant/config.py pattern (env-based credentials, no secrets in git).

If mcp-github can open a PR on sg-tf-demo-org/demo-devsecops-pipeline, do so and return the PR URL. If that repo does not exist yet, output the exact remediating file contents / branch plan as the "fix raised" artifact and say the PR target repo is next.
Do not reintroduce secrets. STOP with the fix artifact.""",
    ),
    (
        "semgrep_v",
        "Semgrep — violation found",
        """Use persona devops-pipeline-engineer. Load skill explain-devsecops-gate.

Semgrep FAILED on fixtures/vulnerable/sql_helper.py: SQL built with string concatenation of username, and pickle.loads on a session blob.

Figure out the problem: name the gate (Semgrep), cite the insecure patterns (SQL injection / insecure deserialization), and state why the PR cannot merge. Diagnosis only — no fix yet. STOP.""",
    ),
    (
        "semgrep_f",
        "Semgrep — fix raised",
        """Use persona devops-pipeline-engineer. Load skill remediate-devsecops-findings.

Semgrep failed on vulnerable sql_helper.py. Raise the FIX matching fixtures/compliant/sql_helper.py: parameterized SQL (? placeholders) and no pickle.loads on untrusted input.

Open a PR via mcp-github if demo-devsecops-pipeline exists; otherwise deliver the remediating file as the fix artifact. STOP with PR URL or fix contents.""",
    ),
    (
        "trivy_v",
        "Trivy fs/image — violation found",
        """Use persona devops-pipeline-engineer. Load skill explain-devsecops-gate.

Trivy filesystem scan FAILED on fixtures/vulnerable/requirements.txt (urllib3==1.26.5 — e.g. CVE-2021-33503 class findings) and/or Trivy image would FAIL on fixtures/vulnerable/Dockerfile FROM python:3.8.0-slim (HIGH/CRITICAL).

Figure out the problem: name Trivy fs vs Trivy image, what severity blocks the pipeline, and why merge/push is blocked. Diagnosis only. STOP.""",
    ),
    (
        "trivy_f",
        "Trivy — fix raised",
        """Use persona devops-pipeline-engineer. Load skill remediate-devsecops-findings.

Trivy blocked vulnerable requirements and/or python:3.8.0-slim. Raise the FIX: fixtures/compliant/requirements.txt (urllib3>=2.2.0, requests>=2.32.0) and fixtures/compliant/Dockerfile (python:3.12-slim).

PR via mcp-github if possible; else deliver remediating files as the fix artifact. STOP.""",
    ),
    (
        "cosign_v",
        "Cosign — violation / missing trust found",
        """Use persona devops-pipeline-engineer. Load skill explain-devsecops-gate.

In the DevSecOps pipeline, an image that failed Trivy never reaches cosign. Separately: if cosign verify fails or the image is unsigned, the CI trust-anchor step fails (image-build.yml: cosign sign then cosign verify).

Figure out the problem: explain cosign's role AFTER Trivy passes, what "unsigned / verify failed" means for the pipeline, and that v1 does NOT enforce signatures in Kyverno yet. Diagnosis of the trust-anchor gap. STOP.""",
    ),
    (
        "cosign_f",
        "Cosign — fix raised",
        """Use persona devops-pipeline-engineer. Load skill remediate-devsecops-findings.

Raise the FIX path for cosign: ensure image-build.yml builds the COMPLIANT Dockerfile, Trivy image exits 0, then cosign generate-key-pair (or COSIGN_KEY secret), cosign sign, cosign verify — print that verify OK is the required green check.

If you can open/update a PR that only uses fixtures/compliant for the image job, do so; else describe the exact workflow fix as the raised remedation. STOP.""",
    ),
    (
        "kyverno_v",
        "Kyverno — violation found",
        """Use persona devops-pipeline-engineer. Load skill explain-devsecops-gate.

kubectl apply of fixtures/vulnerable/bad-pod.yaml in namespace devsecops-demo was DENIED by Kyverno. The pod is privileged: true, allowPrivilegeEscalation: true, has no resource limits, and uses nginx:latest.

Figure out the problem: name which namespaced policies fire (deny-privileged, require-resource-limits, deny-latest-tag), quote the violating fields, and stress this ns is ONLY devsecops-demo (not otel-demo). Diagnosis only. STOP.""",
    ),
    (
        "kyverno_f",
        "Kyverno — fix raised",
        """Use persona devops-pipeline-engineer. Load skill remediate-devsecops-findings.

Kyverno denied the bad pod. Raise the FIX: fixtures/compliant/good-pod.yaml (non-priv, limits, nginx:1.27.3 pinned). Open a PR if the demo repo exists; otherwise deliver the good-pod manifest as the fix artifact and the command `bash devsecops-demo/scripts/demo_admit_bad_pod.sh good` for HITL re-admit.

Never apply outside namespace devsecops-demo. STOP.""",
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
    c, ag = guild("GET", f"/guild/api/v1/agents/{AGENT}")
    if c != 200:
        print(f"Agent missing HTTP {c} — run register_devops_pipeline_engineer_aiden.py", flush=True)
        return 1
    print(f"agent ok {AGENT}", flush=True)

    results = []
    for beat, title, msg in PROMPTS:
        if beat not in WANT:
            continue
        print(f"==> {beat}: {title}", flush=True)
        try:
            sid = start_chat(msg)
            print(f"    session={sid}", flush=True)
            print(f"    watch={watch_url(sid)}", flush=True)
            row = poll(sid)
            row.update({"beat": beat, "title": title})
            results.append(row)
            print(f"    status={row.get('status')}", flush=True)
        except Exception as e:
            results.append({"beat": beat, "title": title, "error": str(e), "watch": None})
            print(f"    ERROR {e}", flush=True)

    OUT.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {OUT}\n", flush=True)

    # Markdown table for presenter
    print("| Step | Tool / action | Watch |", flush=True)
    print("|------|---------------|-------|", flush=True)
    for r in results:
        w = r.get("watch") or r.get("error")
        print(f"| {r.get('beat')} | {r.get('title')} | {w} |", flush=True)
    return 0 if all(r.get("watch") for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
