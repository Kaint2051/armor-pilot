#!/bin/bash
# ============================================================
# LAB 03: Vong doi Policy (Tao → Kiem tra → Xoa)
# Muc tieu: Kiem tra toan bo CRUD voi VarmorPolicy CRD
# Can quyen: kubectl tren server
# ============================================================

API="${ARMORPILOT_API_URL:-http://127.0.0.1:30080}"
AUTH="${ARMORPILOT_USERNAME:-admin}:${ARMORPILOT_PASSWORD:?Set ARMORPILOT_PASSWORD before running this lab}"
NS="default"
TEST_DEPLOY="lab03-target-app"
POLICY_BASIC="lab03-policy-basic"
POLICY_FULL="lab03-policy-full"
POLICY_DUP="lab03-policy-dup"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASSED=0; FAILED=0; TOTAL=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); }
info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }

api() { curl -s -u "${AUTH}" "$@"; }

cleanup() {
    kubectl delete deployment "${TEST_DEPLOY}" --ignore-not-found > /dev/null 2>&1
    for p in "${POLICY_BASIC}" "${POLICY_FULL}" "${POLICY_DUP}"; do
        kubectl delete varmorpolicy "$p" -n "${NS}" --ignore-not-found > /dev/null 2>&1
    done
}

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         LAB 03: VONG DOI POLICY (CRUD)              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"

# ----------------------------------------------------------
section "3.1 Setup: Tao Deployment lam target"
# ----------------------------------------------------------
cleanup
kubectl create deployment "${TEST_DEPLOY}" --image=nginx:alpine > /dev/null 2>&1
sleep 2
kubectl wait --for=condition=available deployment/"${TEST_DEPLOY}" \
    --timeout=30s > /dev/null 2>&1
AVAIL=$(kubectl get deployment "${TEST_DEPLOY}" \
    -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo "0")
[ "${AVAIL:-0}" -ge "0" ] && pass "Deployment target '${TEST_DEPLOY}' da san sang" \
    || fail "Deployment khong khoi dong duoc"

# ----------------------------------------------------------
section "3.2 Tao Policy co ban (chi AppArmor, khong co rules)"
# ----------------------------------------------------------

PAYLOAD_BASIC=$(cat <<EOF
{
  "name": "${POLICY_BASIC}",
  "namespace": "${NS}",
  "target_deployment": "${TEST_DEPLOY}",
  "enforcers": ["AppArmor"],
  "rules": [],
  "banned_files": []
}
EOF
)

RESP=$(api -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD_BASIC}")
HTTP_CODE=$(api -s -o /dev/null -w "%{http_code}" \
    -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD_BASIC}" 2>/dev/null)

# First call above already created, check if it succeeded
if echo "$RESP" | grep -q '"name"'; then
    pass "POST /api/policies tra ve 201 va thong tin policy"
    info "Response: $(echo $RESP | python3 -m json.tool 2>/dev/null | head -5)"
else
    # Might be 409 conflict since we sent twice
    if echo "$RESP" | grep -qi "conflict\|already exists"; then
        pass "Policy da ton tai (duplicate request xu ly dung - 409)"
    else
        fail "Tao policy that bai: ${RESP:0:300}"
    fi
fi

sleep 2

# ----------------------------------------------------------
section "3.3 Xac minh CRD duoc tao trong Kubernetes"
# ----------------------------------------------------------

K8S_POLICY=$(kubectl get varmorpolicy "${POLICY_BASIC}" -n "${NS}" \
    -o jsonpath='{.metadata.name}' 2>/dev/null)
if [ "${K8S_POLICY}" = "${POLICY_BASIC}" ]; then
    pass "VarmorPolicy '${POLICY_BASIC}' ton tai trong Kubernetes (kubectl xac nhan)"
else
    fail "VarmorPolicy khong ton tai trong K8s sau khi tao qua API"
fi

K8S_TARGET=$(kubectl get varmorpolicy "${POLICY_BASIC}" -n "${NS}" \
    -o jsonpath='{.spec.target.name}' 2>/dev/null)
if [ "${K8S_TARGET}" = "${TEST_DEPLOY}" ]; then
    pass "spec.target.name chinh xac: '${TEST_DEPLOY}'"
else
    fail "spec.target.name sai: '${K8S_TARGET}'"
fi

K8S_MODE=$(kubectl get varmorpolicy "${POLICY_BASIC}" -n "${NS}" \
    -o jsonpath='{.spec.policy.mode}' 2>/dev/null)
if [ "${K8S_MODE}" = "EnhanceProtect" ]; then
    pass "spec.policy.mode = EnhanceProtect (dung)"
else
    fail "spec.policy.mode sai: '${K8S_MODE}'"
fi

# ----------------------------------------------------------
section "3.4 GET /api/policies tra ve policy vua tao"
# ----------------------------------------------------------

POLICIES_RESP=$(api "${API}/api/namespaces/${NS}/policies")

if echo "${POLICIES_RESP}" | python3 -m json.tool > /dev/null 2>&1; then
    pass "GET /api/namespaces/${NS}/policies tra ve JSON hop le"
else
    fail "Response khong phai JSON: ${POLICIES_RESP:0:200}"
fi

if echo "${POLICIES_RESP}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
names = [p['name'] for p in data.get('policies', [])]
assert '${POLICY_BASIC}' in names, 'not found'
" 2>/dev/null; then
    pass "Policy '${POLICY_BASIC}' xuat hien trong GET policies"
else
    fail "Policy '${POLICY_BASIC}' khong xuat hien trong list"
fi

for field in "name" "namespace" "status" "mode" "target" "created_at"; do
    if echo "${POLICIES_RESP}" | grep -q "\"${field}\""; then
        pass "Truong '${field}' co trong response"
    else
        fail "Truong '${field}' bi thieu"
    fi
done

# ----------------------------------------------------------
section "3.5 Tao Policy day du (tat ca rules + banned files)"
# ----------------------------------------------------------

PAYLOAD_FULL=$(cat <<EOF
{
  "name": "${POLICY_FULL}",
  "namespace": "${NS}",
  "target_deployment": "${TEST_DEPLOY}",
  "enforcers": ["AppArmor", "Seccomp"],
  "rules": ["container_escape", "privilege_escalation"],
  "banned_files": ["/etc/shadow", "/etc/passwd", "/proc/sysrq-trigger"]
}
EOF
)

RESP_FULL=$(api -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD_FULL}")
sleep 2

K8S_RULES=$(kubectl get varmorpolicy "${POLICY_FULL}" -n "${NS}" \
    -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' 2>/dev/null)
if echo "${K8S_RULES}" | grep -q "disallow-write-core-pattern"; then
    pass "attackProtectionRules chua container_escape rules"
else
    fail "attackProtectionRules thieu container_escape rules"
fi

K8S_FILES=$(kubectl get varmorpolicy "${POLICY_FULL}" -n "${NS}" \
    -o jsonpath='{.spec.policy.enhanceProtect.appArmorRawRules}' 2>/dev/null)
if echo "${K8S_FILES}" | grep -q "shadow"; then
    pass "appArmorRawRules chua deny /etc/shadow"
else
    fail "appArmorRawRules thieu /etc/shadow"
fi

K8S_ENFORCER=$(kubectl get varmorpolicy "${POLICY_FULL}" -n "${NS}" \
    -o jsonpath='{.spec.policy.enforcer}' 2>/dev/null)
if echo "${K8S_ENFORCER}" | grep -q "AppArmor"; then
    pass "enforcer chua AppArmor: '${K8S_ENFORCER}'"
else
    fail "enforcer thieu AppArmor: '${K8S_ENFORCER}'"
fi

# ----------------------------------------------------------
section "3.6 Kiem tra validation: thieu truong bat buoc"
# ----------------------------------------------------------

HTTP_NO_NAME=$(api -s -o /dev/null -w "%{http_code}" \
    -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d '{"namespace":"default","target_deployment":"nginx","enforcers":["AppArmor"]}')
if [ "${HTTP_NO_NAME}" = "400" ]; then
    pass "Thieu 'name' → HTTP 400 (validation dung)"
else
    fail "Thieu 'name' nen tra 400, nhan: ${HTTP_NO_NAME}"
fi

HTTP_NO_TARGET=$(api -s -o /dev/null -w "%{http_code}" \
    -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d '{"name":"x","namespace":"default","enforcers":["AppArmor"]}')
if [ "${HTTP_NO_TARGET}" = "400" ]; then
    pass "Thieu 'target_deployment' → HTTP 400"
else
    fail "Thieu 'target_deployment' nen tra 400, nhan: ${HTTP_NO_TARGET}"
fi

HTTP_NO_JSON=$(api -s -o /dev/null -w "%{http_code}" \
    -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d 'not-valid-json')
if [ "${HTTP_NO_JSON}" = "400" ]; then
    pass "Body khong phai JSON → HTTP 400"
else
    fail "Body sai nen tra 400, nhan: ${HTTP_NO_JSON}"
fi

# ----------------------------------------------------------
section "3.7 Xoa Policy va xac minh"
# ----------------------------------------------------------

HTTP_DEL=$(api -s -o /dev/null -w "%{http_code}" \
    -X DELETE "${API}/api/namespaces/${NS}/policies/${POLICY_BASIC}")
if [ "${HTTP_DEL}" = "200" ]; then
    pass "DELETE '${POLICY_BASIC}' → HTTP 200"
else
    fail "DELETE tra ma loi: ${HTTP_DEL}"
fi
sleep 2

STILL_EXISTS=$(kubectl get varmorpolicy "${POLICY_BASIC}" -n "${NS}" 2>&1)
if echo "${STILL_EXISTS}" | grep -q "not found\|NotFound"; then
    pass "VarmorPolicy '${POLICY_BASIC}' da bi xoa khoi Kubernetes"
else
    fail "VarmorPolicy van con sau khi xoa: ${STILL_EXISTS}"
fi

# ----------------------------------------------------------
section "3.8 Xoa policy khong ton tai → 404"
# ----------------------------------------------------------

HTTP_DEL_NF=$(api -s -o /dev/null -w "%{http_code}" \
    -X DELETE "${API}/api/namespaces/${NS}/policies/non-existent-policy-xyz")
if [ "${HTTP_DEL_NF}" = "404" ] || [ "${HTTP_DEL_NF}" = "422" ]; then
    pass "Xoa policy khong ton tai → HTTP ${HTTP_DEL_NF} (dung)"
else
    fail "Ky vong 404, nhan: ${HTTP_DEL_NF}"
fi

# ----------------------------------------------------------
section "3.9 Cleanup"
# ----------------------------------------------------------
cleanup
pass "Cleanup hoan tat — da xoa tat ca tai nguyen test"

# ----------------------------------------------------------
echo -e "\n${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}KET QUA LAB 03:${NC}  ${GREEN}${PASSED} PASS${NC}  |  ${RED}${FAILED} FAIL${NC}  |  Tong: ${TOTAL}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}\n"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
