#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"
NAMESPACE="default"
SECRET_NAME="armor-pilot-secret"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing ${ENV_FILE}. Copy .env.example to .env and configure it first." >&2
  exit 1
fi

if grep -Eq 'REPLACE_WITH|<configured-|changeme|abc@123' "${ENV_FILE}"; then
  echo "${ENV_FILE} still contains an insecure placeholder." >&2
  exit 1
fi

if ! grep -Eq '^ADMIN_USER=.+$' "${ENV_FILE}" || ! grep -Eq '^ADMIN_PASS=.{12,}$' "${ENV_FILE}"; then
  echo "${ENV_FILE} must define ADMIN_USER and an ADMIN_PASS of at least 12 characters." >&2
  exit 1
fi

chmod 600 "${ENV_FILE}"

kubectl create secret generic "${SECRET_NAME}" \
  --namespace "${NAMESPACE}" \
  --from-env-file="${ENV_FILE}" \
  --dry-run=client \
  -o yaml | kubectl apply -f -

kubectl apply -f "${REPO_ROOT}/k8s/rbac.yaml"
kubectl apply -f "${REPO_ROOT}/k8s/deployment.yaml"
kubectl rollout restart deployment/armor-pilot --namespace "${NAMESPACE}"
kubectl rollout status deployment/armor-pilot --namespace "${NAMESPACE}" --timeout=180s

echo "ArmorPilot is ready. The private environment remains in ${ENV_FILE}."
