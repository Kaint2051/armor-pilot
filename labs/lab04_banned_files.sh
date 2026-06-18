#!/bin/bash
# ============================================================
# LAB 04: Kiem tra chan truy cap File nhay cam (Banned Files)
# Muc tieu: Xac nhan policy fileRules chan doc/ghi file he thong
# Luu y: Can varmor-agent RUNNING de thuc thi. Lab nay kiem tra
#        ca tren mang phang quan ly (API) lan lop thuc thi (pod).
# ============================================================

API="${ARMORPILOT_API_URL:-http://127.0.0.1:30080}"
AUTH="${ARMORPILOT_USERNAME:-admin}:${ARMORPILOT_PASSWORD:?Set ARMORPILOT_PASSWORD before running this lab}"
NS="default"
TEST_DEPLOY="lab04-target-app"
TEST_POLICY="lab04-banned-files-policy"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASSED=0; FAILED=0; TOTAL=0; SKIPPED=0

pass()  { echo -e "  ${GREEN}[PASS]${NC} $1";   PASSED=$((PASSED+1));  TOTAL=$((TOTAL+1)); }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1";    FAILED=$((FAILED+1));  TOTAL=$((TOTAL+1)); }
skip()  { echo -e "  ${YELLOW}[SKIP]${NC} $1"; SKIPPED=$((SKIPPED+1)); }
info()  { echo -e "  ${BLUE}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }

api() { curl -s -u "${AUTH}" "$@"; }

cleanup() {
    kubectl delete deployment "${TEST_DEPLOY}" --ignore-not-found > /dev/null 2>&1
    kubectl delete varmorpolicy "${TEST_POLICY}" -n "${NS}" --ignore-not-found > /dev/null 2>&1
    sleep 2
}

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║       LAB 04: CHAN TRUY CAP FILE NHAY CAM            ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"

# Kiem tra varmor-agent
AGENT_STATUS=$(kubectl get pods -n varmor -l app=varmor-agent \
    -o jsonpath='{.items[0].status.phase}' 2>/dev/null)
AGENT_READY=$(kubectl get pods -n varmor -l app=varmor-agent \
    -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)

info "varmor-agent status: ${AGENT_STATUS:-unknown}, ready: ${AGENT_READY:-unknown}"
AGENT_OK=false
[ "${AGENT_READY}" = "true" ] && AGENT_OK=true

# ----------------------------------------------------------
section "4.1 Tao Deployment va Policy voi Banned Files"
# ----------------------------------------------------------
cleanup

kubectl create deployment "${TEST_DEPLOY}" --image=ubuntu:22.04 \
    -- sleep infinity > /dev/null 2>&1
kubectl wait --for=condition=available deployment/"${TEST_DEPLOY}" \
    --timeout=30s > /dev/null 2>&1 || true

PAYLOAD=$(cat <<EOF
{
  "name": "${TEST_POLICY}",
  "namespace": "${NS}",
  "target_deployment": "${TEST_DEPLOY}",
  "enforcers": ["AppArmor"],
  "rules": [],
  "banned_files": [
    "/etc/shadow",
    "/etc/passwd",
    "/proc/sys/kernel/core_pattern",
    "/proc/sysrq-trigger",
    "/var/run/docker.sock"
  ]
}
EOF
)

RESP=$(api -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD}")
sleep 3

if echo "$RESP" | grep -q '"name"\|created'; then
    pass "Policy '${TEST_POLICY}' tao thanh cong"
elif echo "$RESP" | grep -qi "conflict\|already"; then
    pass "Policy da ton tai (chap nhan)"
else
    fail "Tao policy that bai: ${RESP:0:300}"
fi

# ----------------------------------------------------------
section "4.2 Xac minh fileRules trong CRD"
# ----------------------------------------------------------

FILE_RULES=$(kubectl get varmorpolicy "${TEST_POLICY}" -n "${NS}" \
    -o jsonpath='{.spec.policy.enhanceProtect.appArmorRawRules}' 2>/dev/null)

info "fileRules da duoc ghi vao CRD:"
echo "${FILE_RULES}" | python3 -m json.tool 2>/dev/null | grep "path" | head -10

for banned_file in "/etc/shadow" "/etc/passwd" "/proc/sysrq-trigger"; do
    if echo "${FILE_RULES}" | grep -q "${banned_file}"; then
        pass "appArmorRawRule deny '${banned_file}' ton tai trong CRD"
    else
        fail "appArmorRawRule deny '${banned_file}' bi thieu"
    fi
done

RAW_SYNTAX=$(kubectl get varmorpolicy "${TEST_POLICY}" -n "${NS}" \
    -o jsonpath='{.spec.policy.enhanceProtect.appArmorRawRules[0].rules}' 2>/dev/null)
if echo "${RAW_SYNTAX}" | grep -q "deny"; then
    pass "AppArmor raw rule su dung cu phap 'deny' (chinh xac)"
else
    fail "AppArmor raw rule thieu cu phap 'deny': ${RAW_SYNTAX}"
fi
if echo "${RAW_SYNTAX}" | grep -q "rwmlk"; then
    pass "AppArmor raw rule chua permissions 'rwmlk'"
else
    fail "AppArmor raw rule thieu permissions: ${RAW_SYNTAX}"
fi

# ----------------------------------------------------------
section "4.3 Kiem tra thuc thi (can varmor-agent RUNNING)"
# ----------------------------------------------------------

POD_NAME=$(kubectl get pods -l "app=${TEST_DEPLOY}" -n "${NS}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
info "Pod target: ${POD_NAME:-'chua co'}"

if [ "${AGENT_OK}" = "true" ] && [ -n "${POD_NAME}" ]; then
    info "varmor-agent dang chay — kiem tra thuc thi thuc te"
    sleep 10  # Cho policy duoc ap dung

    # Thu doc /etc/shadow — phai bi chan
    SHADOW_READ=$(kubectl exec "${POD_NAME}" -n "${NS}" -- \
        cat /etc/shadow 2>&1 || true)
    if echo "${SHADOW_READ}" | grep -qi "permission denied\|operation not permitted"; then
        pass "Bi chan: cat /etc/shadow → Permission denied"
    else
        fail "KHONG BI CHAN: cat /etc/shadow doc duoc noi dung!"
        echo "    Noi dung (3 dong dau): $(echo "${SHADOW_READ}" | head -3)"
    fi

    # Thu ghi /etc/passwd — phai bi chan
    PASSWD_WRITE=$(kubectl exec "${POD_NAME}" -n "${NS}" -- \
        sh -c 'echo "hacker:x:0:0::/root:/bin/bash" >> /etc/passwd 2>&1' || true)
    if echo "${PASSWD_WRITE}" | grep -qi "permission denied\|operation not permitted"; then
        pass "Bi chan: ghi vao /etc/passwd → Permission denied"
    else
        fail "KHONG BI CHAN: Co the ghi vao /etc/passwd!"
    fi

    # Thu truy cap /proc/sysrq-trigger
    SYSRQ=$(kubectl exec "${POD_NAME}" -n "${NS}" -- \
        sh -c 'echo b > /proc/sysrq-trigger 2>&1' || true)
    if echo "${SYSRQ}" | grep -qi "permission denied\|operation not permitted"; then
        pass "Bi chan: ghi /proc/sysrq-trigger → Permission denied"
    else
        fail "KHONG BI CHAN: Co the truy cap /proc/sysrq-trigger!"
    fi

    # File binh thuong van doc duoc
    NORMAL_READ=$(kubectl exec "${POD_NAME}" -n "${NS}" -- \
        cat /etc/hostname 2>&1 || true)
    if echo "${NORMAL_READ}" | grep -qi "permission denied"; then
        fail "File binh thuong /etc/hostname cung bi chan (sai)"
    else
        pass "File binh thuong /etc/hostname van doc duoc (policy chinh xac)"
    fi

else
    skip "varmor-agent khong ready — bo qua kiem tra thuc thi thuc te"
    skip "Ly do: varmor-agent can kernel ho tro AppArmor (khong kha dung tren Kind/Docker)"
    info "Goi y: De test tren moi truong thuc, deploy tren K8s co AppArmor kernel support"
    info "Tuy nhien policy da duoc tao chinh xac trong K8s CRD (xem phan 4.2)"
fi

# ----------------------------------------------------------
section "4.4 Kiem tra Policy hien thi dung trong Console API"
# ----------------------------------------------------------

POL_RESP=$(api "${API}/api/namespaces/${NS}/policies")
if echo "${POL_RESP}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
names = [p['name'] for p in data.get('policies', [])]
assert '${TEST_POLICY}' in names
" 2>/dev/null; then
    pass "Policy hien thi trong GET /api/.../policies"
else
    fail "Policy khong hien thi trong Console API"
fi

# ----------------------------------------------------------
section "4.5 Cleanup"
# ----------------------------------------------------------
cleanup
pass "Cleanup hoan tat"

# ----------------------------------------------------------
echo -e "\n${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}KET QUA LAB 04:${NC}  ${GREEN}${PASSED} PASS${NC}  |  ${RED}${FAILED} FAIL${NC}  |  ${YELLOW}${SKIPPED} SKIP${NC}  |  Tong: ${TOTAL}"
[ "${AGENT_OK}" != "true" ] && \
    echo -e "  ${YELLOW}(!) Cac test thuc thi bi skip vi varmor-agent chua san sang${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}\n"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
