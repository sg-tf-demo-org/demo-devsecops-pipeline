#!/usr/bin/env bash
# Apply / delete DevSecOps demo Pods only in namespace devsecops-demo.
# Never targets otel-demo or other namespaces.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NS="${DEVSECOPS_NS:-devsecops-demo}"
MODE="${1:-bad}"

usage() {
  cat <<EOF
Usage: $0 [bad|good|delete-bad|delete-good|ensure-ns|apply-policies]

  bad            Apply fixtures/vulnerable/bad-pod.yaml (expect Kyverno deny)
  good           Apply fixtures/compliant/good-pod.yaml (expect allow)
  delete-bad     Delete bad-devsecops-pod
  delete-good    Delete good-devsecops-pod
  ensure-ns      Create namespace $NS
  apply-policies Apply policies/kyverno/*.yaml (Policy objects in $NS only)

Env: KUBECONFIG / current context must point at field-engineering (or local kind).
Runner note: on Aiden remote runner field-engineering-eks, run the same kubectl
commands after ensure-ns + apply-policies (HITL).
EOF
}

need_kubectl() {
  command -v kubectl >/dev/null 2>&1 || {
    echo "kubectl required" >&2
    exit 2
  }
}

ensure_ns() {
  kubectl apply -f "$ROOT/policies/kyverno/namespace.yaml"
}

apply_policies() {
  ensure_ns
  # Apply Policy CRs only (skip re-applying namespace if already listed)
  kubectl apply -f "$ROOT/policies/kyverno/deny-privileged.yaml"
  kubectl apply -f "$ROOT/policies/kyverno/require-resource-limits.yaml"
  kubectl apply -f "$ROOT/policies/kyverno/deny-latest-tag.yaml"
  kubectl get policy -n "$NS"
}

case "$MODE" in
  -h | --help | help)
    usage
    ;;
  ensure-ns)
    need_kubectl
    ensure_ns
    ;;
  apply-policies)
    need_kubectl
    apply_policies
    ;;
  bad)
    need_kubectl
    ensure_ns
    echo "==> Applying BAD pod (expect admission deny) in ns/$NS"
    set +e
    kubectl apply -f "$ROOT/fixtures/vulnerable/bad-pod.yaml"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      echo "OK: kubectl failed as expected (Kyverno enforce)."
      exit 0
    fi
    echo "WARN: apply succeeded — policies may not be installed in $NS" >&2
    exit 1
    ;;
  good)
    need_kubectl
    ensure_ns
    echo "==> Applying GOOD pod (expect allow) in ns/$NS"
    kubectl apply -f "$ROOT/fixtures/compliant/good-pod.yaml"
    kubectl -n "$NS" get pod good-devsecops-pod -o wide
    ;;
  delete-bad)
    need_kubectl
    kubectl -n "$NS" delete pod bad-devsecops-pod --ignore-not-found
    ;;
  delete-good)
    need_kubectl
    kubectl -n "$NS" delete pod good-devsecops-pod --ignore-not-found
    ;;
  *)
    usage
    exit 2
    ;;
esac
