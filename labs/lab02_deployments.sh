#!/bin/bash
# ============================================================
# LAB 02: Phat hien Deployment & Trang thai vArmor
# Muc tieu: Kiem tra viec hien thi Deployment va label sandbox
# Can quyen: kubectl tren server
# ============================================================

API="http://127.0.0.1:8080"
AUTH="admin:Admin@vArmor2026!"
NS="default"
TEST_DEPLOY="lab02-nginx-test"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASSED=0; FAILED=0; TOTAL=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); }
info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }

api_get() { curl -s -u "${AUTH}" "$@"; }

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║      LAB 02: PHAT HIEN DEPLOYMENT & TRANG THAI      ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"

# ----------------------------------------------------------
section "2.1 Setup: Tao Deployment test khong co label vArmor"
# ----------------------------------------------------------

info "Xoa deployment cu neu ton tai..."
kubectl delete deployment "${TEST_DEPLOY}" --ignore-not-found > /dev/null 2>&1
sleep 2

info "Tao nginx deployment khong co vArmor label..."
kubectl create deployment "${TEST_DEPLOY}" --image=nginx:alpine --replicas=1 \
    > /dev/null 2>&1

info "Cho pod ready (toi da 30s)..."
kubectl wait --for=condition=available deployment/"${TEST_DEPLOY}" \
    --timeout=30s > /dev/null 2>&1

DEPLOY_STATUS=$(kubectl get deployment "${TEST_DEPLOY}" \
    -o jsonpath='{.status.availableReplicas}' 2>/dev/null)
if [ "${DEPLOY_STATUS}" = "1" ]; then
    pass "Deployment '${TEST_DEPLOY}' dang chay (1/1 ready)"
else
    warn "Deployment chua ready, tiep tuc kiem tra API (pod co the con khoi dong)"
fi

# ----------------------------------------------------------
section "2.2 API tra ve danh sach Deployment chinh xac"
# ----------------------------------------------------------

RESP=$(api_get "${API}/api/namespaces/${NS}/deployments")

if echo "$RESP" | python3 -m json.tool > /dev/null 2>&1; then
    pass "Response /deployments la JSON hop le"
else
    fail "Response khong phai JSON: ${RESP:0:200}"
fi

NAMES=$(echo "$RESP" | python3 -c \
    "import sys,json; data=json.load(sys.stdin); [print(d['name']) for d in data.get('deployments',[])]" \
    2>/dev/null)
info "Cac deployment hien tai: $(echo $NAMES | tr '\n' ' ')"

if echo "$NAMES" | grep -q "${TEST_DEPLOY}"; then
    pass "Deployment '${TEST_DEPLOY}' xuat hien trong API response"
else
    fail "Deployment '${TEST_DEPLOY}' khong xuat hien trong response"
fi

# ----------------------------------------------------------
section "2.3 Kiem tra truong varmor_enabled = false (chua co label)"
# ----------------------------------------------------------

VARMOR_STATUS=$(echo "$RESP" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data.get('deployments', []):
    if d['name'] == '${TEST_DEPLOY}':
        print(d.get('varmor_enabled', 'N/A'))
" 2>/dev/null)

info "varmor_enabled cho '${TEST_DEPLOY}': ${VARMOR_STATUS}"
if [ "${VARMOR_STATUS}" = "False" ]; then
    pass "varmor_enabled = False (chua co label sandbox)"
else
    fail "Ky vong False, nhan: ${VARMOR_STATUS}"
fi

# ----------------------------------------------------------
section "2.4 Them label vArmor — kiem tra badge 'Protected'"
# ----------------------------------------------------------

info "Them label sandbox.varmor.org/enable=true vao deployment..."
kubectl label deployment "${TEST_DEPLOY}" \
    "sandbox.varmor.org/enable=true" --overwrite > /dev/null 2>&1
sleep 1

RESP2=$(api_get "${API}/api/namespaces/${NS}/deployments")

VARMOR_STATUS2=$(echo "$RESP2" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data.get('deployments', []):
    if d['name'] == '${TEST_DEPLOY}':
        print(d.get('varmor_enabled', 'N/A'))
" 2>/dev/null)

info "varmor_enabled sau khi them label: ${VARMOR_STATUS2}"
if [ "${VARMOR_STATUS2}" = "True" ]; then
    pass "varmor_enabled = True sau khi them label (Protected)"
else
    fail "Ky vong True, nhan: ${VARMOR_STATUS2}"
fi

# ----------------------------------------------------------
section "2.5 Kiem tra thong tin replicas chinh xac"
# ----------------------------------------------------------

REPLICAS=$(echo "$RESP2" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data.get('deployments', []):
    if d['name'] == '${TEST_DEPLOY}':
        print(d.get('replicas', 0))
" 2>/dev/null)

if [ "${REPLICAS}" = "1" ]; then
    pass "Truong replicas = 1 (chinh xac)"
else
    fail "Truong replicas khong dung: ${REPLICAS}"
fi

# ----------------------------------------------------------
section "2.6 Kiem tra namespace khac (kube-system)"
# ----------------------------------------------------------

RESP_SYS=$(api_get "${API}/api/namespaces/kube-system/deployments")
if echo "$RESP_SYS" | python3 -m json.tool > /dev/null 2>&1; then
    pass "API namespace kube-system tra ve JSON hop le"
    COUNT=$(echo "$RESP_SYS" | python3 -c \
        "import sys,json; print(len(json.load(sys.stdin).get('deployments',[])))" 2>/dev/null)
    info "So deployment trong kube-system: ${COUNT}"
else
    fail "Loi khi truy van kube-system: ${RESP_SYS:0:200}"
fi

# ----------------------------------------------------------
section "2.7 Xac minh cau truc JSON day du cac truong"
# ----------------------------------------------------------

FIELDS_OK=true
REQUIRED_FIELDS=("name" "namespace" "replicas" "ready_replicas" "varmor_enabled")
for field in "${REQUIRED_FIELDS[@]}"; do
    if echo "$RESP2" | python3 -c "
import sys, json
data = json.load(sys.stdin)
deps = data.get('deployments', [])
assert all('${field}' in d for d in deps), 'missing ${field}'
" 2>/dev/null; then
        pass "Truong '${field}' co mat trong moi deployment"
    else
        fail "Truong '${field}' bi thieu trong response"
        FIELDS_OK=false
    fi
done

# ----------------------------------------------------------
section "2.8 Cleanup"
# ----------------------------------------------------------

info "Xoa deployment test..."
kubectl delete deployment "${TEST_DEPLOY}" --ignore-not-found > /dev/null 2>&1
pass "Cleanup hoan tat"

# ----------------------------------------------------------
echo -e "\n${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}KET QUA LAB 02:${NC}  ${GREEN}${PASSED} PASS${NC}  |  ${RED}${FAILED} FAIL${NC}  |  Tong: ${TOTAL}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}\n"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
