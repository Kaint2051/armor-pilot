#!/bin/bash
# ============================================================
# LAB 06: Xac minh Audit Log
# Muc tieu: Dam bao moi hanh dong quan trong deu duoc ghi log
#           dung format va dung noi dung
# ============================================================

API="http://127.0.0.1:8080"
AUTH="admin:Admin@ArmorPilot2026!"
NS="default"
POLICY_LOG_TEST="lab06-audit-log-policy"
DEPLOY_LOG_TEST="lab06-audit-target"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASSED=0; FAILED=0; TOTAL=0

pass()  { echo -e "  ${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1"; FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); }
info()  { echo -e "  ${BLUE}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }

api() { curl -s -u "${AUTH}" "$@"; }

# Lay ten pod Console
get_pod() {
    kubectl get pods -l app=armor-pilot -n default \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# Lay log tu pod, chi lay AUDIT lines
get_audit_logs() {
    local pod="$1" since="${2:-30s}"
    kubectl logs "${pod}" --since="${since}" 2>/dev/null | grep '\[AUDIT\]'
}

cleanup() {
    kubectl delete deployment "${DEPLOY_LOG_TEST}" --ignore-not-found > /dev/null 2>&1
    kubectl delete varmorpolicy "${POLICY_LOG_TEST}" -n "${NS}" --ignore-not-found > /dev/null 2>&1
    sleep 1
}

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         LAB 06: XAC MINH AUDIT LOG                  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"

CONSOLE_POD=$(get_pod)
info "Console pod: ${CONSOLE_POD}"
if [ -z "${CONSOLE_POD}" ]; then
    fail "Khong tim thay console pod — ket thuc lab"
    exit 1
fi

cleanup

# ----------------------------------------------------------
section "6.1 Setup: Tao Deployment test"
# ----------------------------------------------------------
kubectl create deployment "${DEPLOY_LOG_TEST}" \
    --image=nginx:alpine > /dev/null 2>&1
sleep 2
pass "Deployment test san sang"

# ----------------------------------------------------------
section "6.2 Hanh dong CREATE — Kiem tra Audit Log"
# ----------------------------------------------------------

TIMESTAMP_BEFORE=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
info "Thoi diem truoc CREATE: ${TIMESTAMP_BEFORE}"

# Thuc hien CREATE
RESP=$(api -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"${POLICY_LOG_TEST}\",
      \"namespace\": \"${NS}\",
      \"target_deployment\": \"${DEPLOY_LOG_TEST}\",
      \"enforcers\": [\"AppArmor\"],
      \"rules\": [\"container_escape\"],
      \"banned_files\": [\"/etc/shadow\"]
    }")
sleep 3

# Lay audit logs sau hanh dong
AUDIT_LOGS=$(kubectl logs "${CONSOLE_POD}" --since=30s 2>/dev/null | grep '\[AUDIT\]')
info "Audit logs (30s gan nhat):"
echo "${AUDIT_LOGS}" | head -10

# Kiem tra log CREATE xuat hien
if echo "${AUDIT_LOGS}" | grep -q "action=CREATE"; then
    pass "AUDIT log ghi nhan action=CREATE"
else
    fail "Khong tim thay action=CREATE trong audit log"
fi

if echo "${AUDIT_LOGS}" | grep -q "policy=${POLICY_LOG_TEST}"; then
    pass "AUDIT log chua ten policy '${POLICY_LOG_TEST}'"
else
    fail "Audit log thieu ten policy"
fi

if echo "${AUDIT_LOGS}" | grep -q "namespace=${NS}"; then
    pass "AUDIT log chua namespace '${NS}'"
else
    fail "Audit log thieu namespace"
fi

if echo "${AUDIT_LOGS}" | grep -q "user=admin"; then
    pass "AUDIT log chua username 'admin'"
else
    fail "Audit log thieu username"
fi

if echo "${AUDIT_LOGS}" | grep -q "status=SUCCESS"; then
    pass "AUDIT log ghi trang thai SUCCESS"
else
    fail "Audit log thieu status=SUCCESS"
fi

# Kiem tra format timestamp
LOG_LINE=$(echo "${AUDIT_LOGS}" | grep "action=CREATE" | tail -1)
info "Log line: ${LOG_LINE}"
if echo "${LOG_LINE}" | grep -qE '^\[20[0-9]{2}-[0-9]{2}-[0-9]{2}T'; then
    pass "Format timestamp ISO 8601 chuan: [YYYY-MM-DDTHH:MM:SSZ]"
else
    fail "Format timestamp sai: ${LOG_LINE:0:30}"
fi

if echo "${LOG_LINE}" | grep -q '\[AUDIT\]'; then
    pass "Log chua marker [AUDIT] ro rang"
else
    fail "Log thieu marker [AUDIT]"
fi

# ----------------------------------------------------------
section "6.3 Hanh dong DELETE — Kiem tra Audit Log"
# ----------------------------------------------------------

api -X DELETE "${API}/api/namespaces/${NS}/policies/${POLICY_LOG_TEST}" > /dev/null
sleep 3

AUDIT_LOGS_DEL=$(kubectl logs "${CONSOLE_POD}" --since=20s 2>/dev/null | grep '\[AUDIT\]')

if echo "${AUDIT_LOGS_DEL}" | grep -q "action=DELETE"; then
    pass "AUDIT log ghi nhan action=DELETE"
else
    fail "Khong tim thay action=DELETE trong audit log"
fi

if echo "${AUDIT_LOGS_DEL}" | grep "action=DELETE" | grep -q "status=SUCCESS"; then
    pass "DELETE audit log co status=SUCCESS"
else
    fail "DELETE audit log thieu status=SUCCESS"
fi

# ----------------------------------------------------------
section "6.4 Kiem tra FAILURE duoc log khi tao trung (duplicate)"
# ----------------------------------------------------------

# Tao policy da bi xoa → gio tao lai de co SUCCESS
api -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"${POLICY_LOG_TEST}\",
      \"namespace\": \"${NS}\",
      \"target_deployment\": \"${DEPLOY_LOG_TEST}\",
      \"enforcers\": [\"AppArmor\"],
      \"rules\": [],
      \"banned_files\": []
    }" > /dev/null
sleep 2

# Tao lan 2 → 409 Conflict → FAILURE log
api -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"${POLICY_LOG_TEST}\",
      \"namespace\": \"${NS}\",
      \"target_deployment\": \"${DEPLOY_LOG_TEST}\",
      \"enforcers\": [\"AppArmor\"],
      \"rules\": [],
      \"banned_files\": []
    }" > /dev/null
sleep 3

AUDIT_LOGS_FAIL=$(kubectl logs "${CONSOLE_POD}" --since=30s 2>/dev/null | grep '\[AUDIT\]')
if echo "${AUDIT_LOGS_FAIL}" | grep -q "status=FAILURE"; then
    pass "AUDIT log ghi nhan status=FAILURE khi tao trung policy"
else
    fail "Khong tim thay status=FAILURE trong audit log"
fi

if echo "${AUDIT_LOGS_FAIL}" | grep "status=FAILURE" | grep -q "details="; then
    pass "FAILURE log chua truong 'details' mo ta ly do loi"
else
    fail "FAILURE log thieu truong 'details'"
fi

# ----------------------------------------------------------
section "6.5 Kiem tra log duoc day ra STDOUT (co the thu thap)"
# ----------------------------------------------------------

# Kiem tra gunicorn access log cung co
ACCESS_LOG=$(kubectl logs "${CONSOLE_POD}" --since=60s 2>/dev/null | \
    grep -v '\[AUDIT\]' | grep -E 'GET|POST|DELETE' | head -5)
if [ -n "${ACCESS_LOG}" ]; then
    pass "Gunicorn access log also available on STDOUT"
    info "Vi du access log: $(echo "${ACCESS_LOG}" | head -2)"
else
    fail "Access log khong tim thay tren STDOUT"
fi

# Kiem tra co the filter log bang label
POD_LABELS=$(kubectl get pod "${CONSOLE_POD}" \
    -o jsonpath='{.metadata.labels}' 2>/dev/null)
if echo "${POD_LABELS}" | grep -q "app.*armor-pilot"; then
    pass "Pod co label app=armor-pilot (de filter log voi kubectl/Loki)"
else
    fail "Pod thieu label de filter log"
fi

# ----------------------------------------------------------
section "6.6 Tong hop format Audit Log"
# ----------------------------------------------------------
info "Tat ca AUDIT events trong 60 giay gan nhat:"
ALL_AUDIT=$(kubectl logs "${CONSOLE_POD}" --since=60s 2>/dev/null | grep '\[AUDIT\]')
echo "$ALL_AUDIT" | while IFS= read -r line; do
    echo "    $line"
done

AUDIT_COUNT=$(echo "$ALL_AUDIT" | grep -c '\[AUDIT\]' || true)
info "Tong so audit events: ${AUDIT_COUNT}"
if [ "${AUDIT_COUNT}" -ge 2 ]; then
    pass "Du so luong audit events (>= 2)"
else
    fail "Qua it audit events: ${AUDIT_COUNT}"
fi

# ----------------------------------------------------------
section "6.7 Cleanup"
# ----------------------------------------------------------
cleanup
pass "Cleanup hoan tat"

# ----------------------------------------------------------
echo -e "\n${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}KET QUA LAB 06:${NC}  ${GREEN}${PASSED} PASS${NC}  |  ${RED}${FAILED} FAIL${NC}  |  Tong: ${TOTAL}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}\n"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
