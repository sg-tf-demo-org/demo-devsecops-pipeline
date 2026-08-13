# DevSecOps pipeline — smoke prompts

**Guild:** stage [`devops-copilot`](https://stage.dev.stackgen.com/app/settings/workspace/devops-copilot/)  
**Persona only:** **`devops-pipeline-engineer`**  
**Do not use:** `stackgen-infra-provisioner`, `infrastructure-engineer`

Prefix each run with: `Use persona devops-pipeline-engineer.`

Cheat sheet: [docs/demo-devsecops-pipeline.md](../../docs/demo-devsecops-pipeline.md)

---

## 0. Thesis (presenter, no agent required)

> Security after deployment is incident response. DevSecOps is a pipeline architecture decision. Aiden is the harness that walks the developer through open-source gates — Gitleaks, Semgrep, Trivy, cosign, Kyverno — so insecure code cannot reach a node unnoticed.

---

## 1. Secrets / Gitleaks (fail then remediate)

```text
Use persona devops-pipeline-engineer. Load skills explain-devsecops-gate and remediate-devsecops-findings.
Add a debug AWS access key to the demo app config (use the vulnerable fixture pattern from the DevSecOps pack) and open a PR on the DevSecOps demo repo when available, or describe the PR path against fixtures/vulnerable/config.py.
Do not silently remove the secret on the first PR — we need Gitleaks to fail.
```

Follow-up after red check:

```text
Use persona devops-pipeline-engineer. Gitleaks failed on the debug key PR. Explain which gate failed, then open a remediating change using the compliant config (env-based credentials, no hardcoded secrets).
```

---

## 2. SAST / Semgrep

```text
Use persona devops-pipeline-engineer. Load skills explain-devsecops-gate and remediate-devsecops-findings.
Add a Python helper that builds SQL with string concatenation and uses pickle.loads on a session blob (vulnerable fixture pattern). Open a PR or branch so Semgrep can fail.
```

Follow-up:

```text
Use persona devops-pipeline-engineer. Semgrep failed on the SQL/pickle helper. Explain the rules, then remediate with parameterized SQL and no pickle.loads on untrusted input (compliant fixture).
```

---

## 3. Dependencies + image + cosign (Trivy)

```text
Use persona devops-pipeline-engineer. Load skills explain-devsecops-gate and remediate-devsecops-findings.
Ship the vulnerable requirements pin (urllib3==1.26.5) and the vulnerable Dockerfile base python:3.8.0-slim so Trivy fs / image gates fail. Summarize expected HIGH/CRITICAL findings (e.g. CVE-2021-33503 on urllib3).
```

Follow-up:

```text
Use persona devops-pipeline-engineer. Trivy blocked the image/deps. Remediate using compliant requirements and python:3.12-slim. After a green image job, call out that cosign sign+verify in CI is the trust anchor (cluster signature enforcement is out of scope for v1).
```

---

## 4. Admission / Kyverno (namespace devsecops-demo only)

Presenter (cluster, HITL):

```bash
bash devsecops-demo/scripts/demo_admit_bad_pod.sh apply-policies
bash devsecops-demo/scripts/demo_admit_bad_pod.sh bad    # expect deny
```

Then chat:

```text
Use persona devops-pipeline-engineer. Load skills explain-devsecops-gate and remediate-devsecops-findings.
A Pod apply in namespace devsecops-demo was denied by Kyverno (privileged / no limits / :latest). Explain which policies fired and open or describe a remediating manifest matching fixtures/compliant/good-pod.yaml. Do not apply to otel-demo or any other namespace.
```

Optional allow path:

```bash
bash devsecops-demo/scripts/demo_admit_bad_pod.sh good
```

---

## 5. Close (value line)

> Findings are not a report to SecOps at the end — they are blocking feedback in the developer’s workflow. Aiden (`devops-pipeline-engineer`) authors, explains, and remediates; OSS gates stay the blockers. Winning teams made insecure code unable to reach production without anyone noticing.

---

## Sibling track (do not run inside this story)

Platform IaC UC3 / fire-list UC8 (Trivy+Rego on `field-engineering`) remain a separate talk track — see [demo-platform-iac-five-use-cases.md](../../docs/demo-platform-iac-five-use-cases.md).
