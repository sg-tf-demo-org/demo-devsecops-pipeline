# DevSecOps demo pack (stage Aiden — net-new track)

Open-source pipeline gates + Aiden harness persona **`devops-pipeline-engineer`**.

| Item | Value |
|------|--------|
| Instance | https://stage.dev.stackgen.com — workspace **devops-copilot** |
| Hero persona | **`devops-pipeline-engineer`** |
| Not used | `stackgen-infra-provisioner`, `infrastructure-engineer` |
| Cheat sheet | [docs/demo-devsecops-pipeline.md](../docs/demo-devsecops-pipeline.md) |
| Product Rules | [docs/knowledge-hub/product-rules-devsecops-pipeline.md](../docs/knowledge-hub/product-rules-devsecops-pipeline.md) |
| Smoke prompts | [scripts/smoke_prompts.md](scripts/smoke_prompts.md) |

## Isolation (hard)

- **Do not** edit stage Integrations (https://stage.dev.stackgen.com/app/settings/workspace/devops-copilot/integrations).
- **Do not** modify existing personas, Product Rules, workflows, or `field-engineering` workflows.
- Kyverno policies are **namespaced** to `devsecops-demo` only — never cluster-wide / never `otel-demo`.
- This pack is **local first**; pushing to GitHub is a later step (see below).

## Layout

```
devsecops-demo/
  fixtures/vulnerable/     # fail path (secret, SAST, CVE pin, Dockerfile, bad Pod)
  fixtures/compliant/      # remediating twins
  policies/kyverno/        # Policy CRs + Namespace (ns-scoped)
  .pre-commit-config.yaml  # Gitleaks
  .github/workflows/       # gitleaks, semgrep, trivy-fs, image-build (+ cosign)
  scripts/
```

## Expected fail signals (presenters)

| Gate | Vulnerable fixture | Signal |
|------|-------------------|--------|
| Gitleaks | `fixtures/vulnerable/config.py` | Hardcoded `AKIA…` / fake `ghp_` |
| Semgrep | `fixtures/vulnerable/sql_helper.py` | SQL concat + `pickle.loads` |
| Trivy fs | `fixtures/vulnerable/requirements.txt` | `urllib3==1.26.5` (e.g. CVE-2021-33503) |
| Trivy image | `fixtures/vulnerable/Dockerfile` | `python:3.8.0-slim` |
| Cosign | CI `image-build.yml` | Sign + verify after Trivy pass (compliant path) |
| Kyverno | `fixtures/vulnerable/bad-pod.yaml` | privileged, no limits, `:latest` |

## Local pre-commit

```bash
cd devsecops-demo
pre-commit install
pre-commit run --all-files   # expect fail while vulnerable config is tracked
```

## Kyverno (HITL, ns only)

```bash
bash scripts/demo_admit_bad_pod.sh apply-policies
bash scripts/demo_admit_bad_pod.sh bad     # expect deny
bash scripts/demo_admit_bad_pod.sh good    # expect allow
bash scripts/demo_admit_bad_pod.sh delete-good
```

On Aiden runner **`field-engineering-eks`**: same kubectl after operator approval — never apply outside `devsecops-demo`.

## Additive Guild apply (script — not manual UI busywork)

```bash
export AIDEN_GUILD_TOKEN=…   # stage devops-copilot PAT
export AIDEN_ORG_ID=aee77bee-6885-4b4b-b9c0-e0c7ae81be96
export AIDEN_GUILD_URL=https://stage.dev.stackgen.com
python3 scripts/register_devops_pipeline_engineer_aiden.py
python3 scripts/run_devsecops_smokes.py   # prints watch URLs
```

- Creates **`devops-pipeline-engineer`** + skills `explain-devsecops-gate`, `remediate-devsecops-findings`
- Attaches existing integration **names** `mcp-github` + runner `field-engineering-eks` — **does not** edit the Integrations page
- Demo how-to + seeded watch links: [docs/demo-devsecops-runbook.md](../docs/demo-devsecops-runbook.md)

**Do not:** delete, rename, or reconfigure `stackgen-infra-provisioner` or `infrastructure-engineer`.

Optional UI: paste Product Rules from [product-rules-devsecops-pipeline.md](../docs/knowledge-hub/product-rules-devsecops-pipeline.md) onto the persona if Knowledge Hub API is not used.

## Later: GitHub repo (out of v1 local ship)

When ready for live PR Checks demos:

1. Create **new** repo `sg-tf-demo-org/demo-devsecops-pipeline` (not `field-engineering`).
2. Push this pack (workflows + fixtures).
3. Point smoke prompts / persona defaults at that remote.
4. Leave `field-engineering` and appstack demos alone.

## Story pitch

Aiden (`devops-pipeline-engineer`) is the **AI harness** for DevSecOps: author → OSS gate → explain → remediate → admission. Gates stay open source; Aiden makes the loop operable in chat.
