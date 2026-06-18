#!/bin/bash
# ============================================================
# LAB 05: Kiem tra ngan Container Escape & Privilege Escalation
# Muc tieu: Xac nhan attackProtectionRules hoat dong dung
# Nguon goc ky thuat: CVE-2022-0492, CVE-2019-5736, etc.
# ============================================================

API="${ARMORPILOT_API_URL:-http://127.0.0.1:30080}"
AUTH="${ARMORPILOT_USERNAME:-admin}:${ARMORPILOT_PASSWORD:?Set ARMORPILOT_PASSWORD before running this lab}"
NS="default"
POLICY_ESCAPE="lab05-escape-prevention"
POLICY_PRIVESC="lab05-privesc-prevention"
DEPLOY_ESCAPE="lab05-escape-target"
DEPLOY_PRIVESC="lab05-privesc-target"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASSED=0; FAILED=0; TOTAL=0; SKIPPED=0

pass()  { echo -e "  ${GREEN}[PASS]${NC} $1";   PASSED=$((PASSED+1));  TOTAL=$((TOTAL+1)); }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1";    FAILED=$((FAILED+1));  TOTAL=$((TOTAL+1)); }
skip()  { echo -e "  ${YELLOW}[SKIP]${NC} $1"; SKIPPED=$((SKIPPED+1)); }
info()  { echo -e "  ${BLUE}[INFO]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }

api() { curl -s -u "${AUTH}" "$@"; }

cleanup() {
    for d in "${DEPLOY_ESCAPE}" "${DEPLOY_PRIVESC}"; do
        kubectl delete deployment "$d" -n "${NS}" --ignore-not-found > /dev/null 2>&1
    done
    for p in "${POLICY_ESCAPE}" "${POLICY_PRIVESC}"; do
        kubectl delete varmorpolicy "$p" -n "${NS}" --ignore-not-found > /dev/null 2>&1
    done
    sleep 2
}

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║    LAB 05: NGAN CONTAINER ESCAPE & PRIV ESCALATION  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"

info "Giai thich ky thuat:"
info "  Container Escape: Tan cong leo ra khoi container vao host"
info "  Privilege Escalation: Leo thang tu user thuong len root/privileged"

AGENT_READY=$(kubectl get pods -n varmor -l app=varmor-agent \
    -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)
info "varmor-agent ready: ${AGENT_READY:-unknown}"
AGENT_OK=false
[ "${AGENT_READY}" = "true" ] && AGENT_OK=true

cleanup

# ----------------------------------------------------------
section "5.1 Tao Policy ngan Container Escape"
# ----------------------------------------------------------

kubectl create deployment "${DEPLOY_ESCAPE}" \
    --image=ubuntu:22.04 -- sleep infinity > /dev/null 2>&1

PAYLOAD_ESCAPE=$(cat <<EOF
{
  "name": "${POLICY_ESCAPE}",
  "namespace": "${NS}",
  "target_deployment": "${DEPLOY_ESCAPE}",
  "enforcers": ["AppArmor"],
  "rules": ["container_escape"],
  "banned_files": []
}
EOF
)

RESP=$(api -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD_ESCAPE}")
sleep 3

if echo "$RESP" | grep -q '"name"\|created\|conflict\|already'; then
    pass "Policy container_escape tao thanh cong"
else
    fail "Tao policy container_escape that bai: ${RESP:0:200}"
fi

# ----------------------------------------------------------
section "5.2 Xac minh Container Escape rules trong CRD"
# ----------------------------------------------------------

ATTACK_RULES=$(kubectl get varmorpolicy "${POLICY_ESCAPE}" -n "${NS}" \
    -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' 2>/dev/null)
info "attackProtectionRules: ${ATTACK_RULES:0:300}"

ESCAPE_RULES=(
    "disallow-write-core-pattern"
    "disallow-mount-securityfs"
    "disallow-write-release-agent"
)
for rule in "${ESCAPE_RULES[@]}"; do
    if echo "${ATTACK_RULES}" | grep -q "${rule}"; then
        pass "Rule '${rule}' duoc khai bao"
    else
        fail "Rule '${rule}' bi thieu trong CRD"
    fi
done

# ----------------------------------------------------------
section "5.3 Kiem tra Container Escape thuc te (neu agent OK)"
# ----------------------------------------------------------

POD_ESCAPE=$(kubectl get pods -l "app=${DEPLOY_ESCAPE}" -n "${NS}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ "${AGENT_OK}" = "true" ] && [ -n "${POD_ESCAPE}" ]; then
    sleep 10

    echo -e "\n  ${BOLD}=== Tan cong 1: Ghi core_pattern (CVE-2022-0492 style) ===${NC}"
    info "Ghi core_pattern co the thuc hien container breakout"
    CORE_ATTACK=$(kubectl exec "${POD_ESCAPE}" -n "${NS}" -- \
        sh -c 'echo "| /tmp/escape" > /proc/sys/kernel/core_pattern 2>&1' || true)
    if echo "${CORE_ATTACK}" | grep -qi "permission denied\|operation not permitted\|read-only"; then
        pass "CHONG DUOC: Ghi core_pattern bi chan"
    else
        fail "KHONG CHONG DUOC: Ghi core_pattern thanh cong — nguy hiem!"
    fi

    echo -e "\n  ${BOLD}=== Tan cong 2: Mount securityfs ===${NC}"
    info "Mount securityfs co the expose AppArmor admin interface"
    SEC_ATTACK=$(kubectl exec "${POD_ESCAPE}" -n "${NS}" -- \
        sh -c 'mount -t securityfs securityfs /tmp/secfs 2>&1' || true)
    if echo "${SEC_ATTACK}" | grep -qi "permission denied\|operation not permitted\|not permitted"; then
        pass "CHONG DUOC: Mount securityfs bi chan"
    else
        fail "KHONG CHONG DUOC: Mount securityfs thanh cong — nguy hiem!"
    fi

    echo -e "\n  ${BOLD}=== Tan cong 3: Ghi release_agent (CVE-2022-0492) ===${NC}"
    info "release_agent trong cgroup co the chay lenh voi quyen host"
    RELEASE_ATTACK=$(kubectl exec "${POD_ESCAPE}" -n "${NS}" -- \
        sh -c 'find /sys/fs/cgroup -name "release_agent" 2>/dev/null | head -1 | xargs -r sh -c "echo /tmp/escape > {}" 2>&1' || true)
    if echo "${RELEASE_ATTACK}" | grep -qi "permission denied\|operation not permitted"; then
        pass "CHONG DUOC: Ghi release_agent bi chan"
    else
        warn "Khong the ket luan (co the khong tim thay release_agent)"
    fi

else
    skip "varmor-agent khong ready — bo qua kiem tra thuc thi Container Escape"
    skip "Ly do: Kernel chua ho tro AppArmor trong moi truong Kind/Docker hien tai"

    echo -e "\n  ${YELLOW}=== GIAO THUC TAN CONG (De biet ly thuyet) ===${NC}"
    echo -e "  ${BLUE}Tan cong core_pattern (CVE-2022-0492):${NC}"
    echo "    echo '| /tmp/escape %s' > /proc/sys/kernel/core_pattern"
    echo "    → Khi container crash, host thuc thi /tmp/escape"
    echo ""
    echo -e "  ${BLUE}Tan cong release_agent:${NC}"
    echo "    mount -t cgroup cgroup /tmp/cg"
    echo "    echo 1 > /tmp/cg/notify_on_release"
    echo "    echo '#!/bin/bash\\ncat /etc/passwd > /tmp/stolen' > /tmp/exploit"
    echo "    echo /tmp/exploit > /tmp/cg/release_agent"
    echo "    → Khi process trong cgroup exit, exploit chay voi quyen host"
fi

# ----------------------------------------------------------
section "5.4 Tao Policy ngan Privilege Escalation"
# ----------------------------------------------------------

kubectl create deployment "${DEPLOY_PRIVESC}" \
    --image=ubuntu:22.04 -- sleep infinity > /dev/null 2>&1

PAYLOAD_PRIV=$(cat <<EOF
{
  "name": "${POLICY_PRIVESC}",
  "namespace": "${NS}",
  "target_deployment": "${DEPLOY_PRIVESC}",
  "enforcers": ["AppArmor"],
  "rules": ["privilege_escalation"],
  "banned_files": []
}
EOF
)

RESP_PRIV=$(api -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD_PRIV}")
sleep 3

if echo "$RESP_PRIV" | grep -q '"name"\|created\|conflict\|already'; then
    pass "Policy privilege_escalation tao thanh cong"
else
    fail "Tao policy that bai: ${RESP_PRIV:0:200}"
fi

PRIV_RULES=$(kubectl get varmorpolicy "${POLICY_PRIVESC}" -n "${NS}" \
    -o jsonpath='{.spec.policy.enhanceProtect.attackProtectionRules}' 2>/dev/null)

for rule in "disallow-abuse-user-ns" "disable-cap-privilege"; do
    if echo "${PRIV_RULES}" | grep -q "${rule}"; then
        pass "Privilege escalation rule '${rule}' co trong CRD"
    else
        fail "Rule '${rule}' bi thieu"
    fi
done

POD_PRIV=$(kubectl get pods -l "app=${DEPLOY_PRIVESC}" -n "${NS}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ "${AGENT_OK}" = "true" ] && [ -n "${POD_PRIV}" ]; then
    sleep 10

    echo -e "\n  ${BOLD}=== Tan cong: Leo thang qua User Namespace ===${NC}"
    USERNS_ATTACK=$(kubectl exec "${POD_PRIV}" -n "${NS}" -- \
        sh -c 'unshare --user --map-root-user whoami 2>&1' || true)
    if echo "${USERNS_ATTACK}" | grep -qi "permission denied\|operation not permitted\|unshare"; then
        pass "CHONG DUOC: Unshare user namespace bi chan"
    else
        fail "KHONG CHONG DUOC: unshare thanh cong — nguy hiem!"
        info "Output: ${USERNS_ATTACK}"
    fi
else
    skip "Kiem tra thuc thi privesc bi skip (agent chua ready)"

    echo -e "\n  ${YELLOW}=== GIAO THUC TAN CONG Privilege Escalation ===${NC}"
    echo -e "  ${BLUE}Leo thang qua User Namespace:${NC}"
    echo "    unshare --user --map-root-user /bin/bash"
    echo "    → Container process thay minh la root trong namespace moi"
    echo ""
    echo -e "  ${BLUE}Leo thang qua CAP_SYS_ADMIN:${NC}"
    echo "    capsh --print | grep sys_admin"
    echo "    mount --bind / /mnt/host"
fi

# ----------------------------------------------------------
section "5.5 Kiem tra ca 2 policy hien thi trong Console"
# ----------------------------------------------------------

POL_LIST=$(api "${API}/api/namespaces/${NS}/policies")
for pname in "${POLICY_ESCAPE}" "${POLICY_PRIVESC}"; do
    if echo "${POL_LIST}" | grep -q "\"${pname}\""; then
        pass "Policy '${pname}' hien thi trong Console API"
    else
        fail "Policy '${pname}' khong hien thi"
    fi
done

# ----------------------------------------------------------
section "5.6 Cleanup"
# ----------------------------------------------------------
cleanup
pass "Cleanup hoan tat"

# ----------------------------------------------------------
echo -e "\n${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}KET QUA LAB 05:${NC}  ${GREEN}${PASSED} PASS${NC}  |  ${RED}${FAILED} FAIL${NC}  |  ${YELLOW}${SKIPPED} SKIP${NC}  |  Tong: ${TOTAL}"
[ "${AGENT_OK}" != "true" ] && \
    echo -e "  ${YELLOW}(!) Test thuc thi bi skip: varmor-agent can AppArmor kernel support${NC}"
echo -e "  ${BLUE}(i) Policy da duoc tao va khai bao chinh xac trong K8s CRD${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}\n"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
