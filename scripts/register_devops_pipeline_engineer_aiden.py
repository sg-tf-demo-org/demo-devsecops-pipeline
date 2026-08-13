#!/usr/bin/env python3
"""Register devops-pipeline-engineer + DevSecOps skills on stage Guild (additive only).

Requires: AIDEN_GUILD_TOKEN (or GUILD_TOKEN / STACKGEN_TOKEN)
Optional: AIDEN_ORG_ID, AIDEN_GUILD_URL

Does NOT edit Integrations page settings, stackgen-infra-provisioner, or IE.
Attaches existing integration *names* mcp-github + runner field-engineering-eks.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

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
SKILLS = ("explain-devsecops-gate", "remediate-devsecops-findings")
ROOT = pathlib.Path(__file__).resolve().parents[2]
PERSONA_PATH = ROOT / "docs" / "aiden-skills" / "devops-pipeline-engineer.persona.md"
SKILL_DIR = ROOT / "docs" / "aiden-skills" / "skills"

if not TOKEN:
    sys.exit("AIDEN_GUILD_TOKEN (or GUILD_TOKEN / STACKGEN_TOKEN) required")


def guild(method: str, path: str, body=None, timeout: int = 90):
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
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = raw[:800]
        return e.code, parsed


def list_skills():
    code, data = guild("GET", "/guild/api/v1/skills?limit=100")
    if code != 200:
        return code, []
    if isinstance(data, list):
        return code, data
    return code, data.get("items") or data.get("skills") or []


def upsert_skill(name: str) -> None:
    path = SKILL_DIR / f"{name}.SKILL.md"
    text = path.read_text()
    code, items = list_skills()
    if code != 200:
        print("list skills failed", code, items)
        sys.exit(1)
    sid = ""
    for s in items:
        if (s.get("name") or "").strip() == name:
            sid = s.get("id") or ""
            break
    body = {"skill_md": text}
    if sid:
        c, out = guild("PUT", f"/guild/api/v1/skills/{sid}", body)
        print("skill update", name, "HTTP", c, (out.get("name") if isinstance(out, dict) else out))
    else:
        c, out = guild("POST", "/guild/api/v1/skills", body)
        print("skill create", name, "HTTP", c, (out.get("name") if isinstance(out, dict) else out))
        if c not in (200, 201):
            print(out)
            sys.exit(1)


def upsert_agent() -> None:
    persona = PERSONA_PATH.read_text()
    code, existing = guild("GET", f"/guild/api/v1/agents/{AGENT}")
    ie_code, ie = guild("GET", "/guild/api/v1/agents/infrastructure-engineer")
    model_names = (ie.get("model_names") if ie_code == 200 and isinstance(ie, dict) else None) or [
        "anthropic-claude-sonnet-4-6"
    ]
    preferred_integrations = ["mcp-github"]
    preferred_runners = ["field-engineering-eks"]
    body = {
        "persona": persona,
        "integrations": preferred_integrations,
        "model_names": model_names if code != 200 else (existing.get("model_names") or model_names),
        "model_config": (existing.get("model_config") if code == 200 else {}) or {},
        "remote_runners": preferred_runners,
        "auto_approve_tools": (existing.get("auto_approve_tools") if code == 200 else [{"tool": "*"}]),
        "auto_deny_tools": ["create_agent"],
        "max_iterations": (existing.get("max_iterations") if code == 200 else 40) or 40,
        "tags": ["devsecops", "gitleaks", "semgrep", "trivy", "cosign", "kyverno", "stage"],
    }
    if code == 200 and isinstance(existing, dict):
        ints = list(existing.get("integrations") or [])
        for extra in preferred_integrations:
            if extra not in ints:
                ints.append(extra)
        body["integrations"] = ints
        runners = list(existing.get("remote_runners") or [])
        for r in preferred_runners:
            if r not in runners:
                runners.append(r)
        body["remote_runners"] = runners or preferred_runners

    if code == 200:
        c, out = guild("PUT", f"/guild/api/v1/agents/{AGENT}", body)
        print("agent update", AGENT, "HTTP", c, out.get("name") if isinstance(out, dict) else out)
    else:
        create_body = {"name": AGENT, **body}
        c, out = guild("POST", "/guild/api/v1/agents", create_body)
        print("agent create", AGENT, "HTTP", c, out.get("name") if isinstance(out, dict) else out)
        if c not in (200, 201):
            print("POST failed:", out)
            sys.exit(1)

    c2, agent = guild("GET", f"/guild/api/v1/agents/{AGENT}")
    if c2 == 200 and isinstance(agent, dict):
        p = agent.get("persona") or ""
        print("verify devops-pipeline-engineer in persona", "devops-pipeline-engineer" in p)
        print("verify skills mentioned", all(s in p for s in SKILLS))
        print("integrations", agent.get("integrations"))
        print("remote_runners", agent.get("remote_runners"))
        print("auto_deny_tools", agent.get("auto_deny_tools"))
    else:
        print("verify GET failed", c2, agent)
        sys.exit(1)


def main() -> int:
    if "lcs.cloud.stackgen.com" in BASE:
        print("Refusing: BASE points at LCS. Use stage only.")
        return 1
    if not PERSONA_PATH.exists():
        print("missing", PERSONA_PATH)
        return 1
    for name in SKILLS:
        if not (SKILL_DIR / f"{name}.SKILL.md").exists():
            print("missing skill", name)
            return 1
        upsert_skill(name)
    upsert_agent()
    print("OK — paste Product Rules from docs/knowledge-hub/product-rules-devsecops-pipeline.md in UI if API unavailable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
