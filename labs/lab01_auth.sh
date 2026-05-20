#!/bin/bash
# ============================================================
# LAB 01: Xác thực & Bảo mật (Authentication & Security)
# Mục tiêu: Kiểm tra toàn bộ cơ chế xác thực Basic Auth
# Chạy trên: server 172.30.2.129 (hoặc bất kỳ máy có curl)
# ============================================================

API="http://127.0.0.1:8080"
VALID_AUTH="admin:Admin@vArmor2026!"
WRONG_PASS="admin:wrongpassword"
WRONG_USER="hacker:Admin@vArmor2026!"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASSED=0; FAILED=0; TOTAL=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); }
info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }

check_http() {
    local desc="$1" expected="$2"
    shift 2
    local actual
    actual=$(curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null)
    if [ "$actual" = "$expected" ]; then
        pass "$desc (HTTP $actual)"
    else
        fail "$desc — ky vong HTTP $expected, nhan HTTP $actual"
    fi
}

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         LAB 01: XAC THUC & BAO MAT                  ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"

# ----------------------------------------------------------
section "1.1 Kiem tra Dashboard (trang HTML)"
# ----------------------------------------------------------

check_http "GET / tra ve HTTP 200" "200" "${API}/"

info "Kiem tra noi dung HTML co chu ky vArmor"
HTML=$(curl -s "${API}/")
if echo "$HTML" | grep -q "vArmor Console"; then
    pass "HTML chua chuoi 'vArmor Console'"
else
    fail "HTML khong chua chu ky he thong"
fi

if echo "$HTML" | grep -q "Authorization"; then
    pass "HTML co logic Basic Auth (tim thay 'Authorization')"
else
    fail "HTML thieu logic Basic Auth"
fi

# ----------------------------------------------------------
section "1.2 Bao ve API - Khong co xac thuc"
# ----------------------------------------------------------

ENDPOINTS=(
    "/api/namespaces/default/deployments"
    "/api/namespaces/default/policies"
    "/api/namespaces/kube-system/deployments"
)

for ep in "${ENDPOINTS[@]}"; do
    check_http "GET $ep khong auth → 401" "401" "${API}${ep}"
done

check_http "POST /api/policies khong auth → 401" "401" \
    -X POST "${API}/api/policies" \
    -H "Content-Type: application/json" \
    -d '{"name":"test","namespace":"default","target_deployment":"nginx","enforcers":["AppArmor"]}'

check_http "DELETE /api/.../policies/x khong auth → 401" "401" \
    -X DELETE "${API}/api/namespaces/default/policies/test-policy"

# ----------------------------------------------------------
section "1.3 Sat thu voi mat khau sai"
# ----------------------------------------------------------

check_http "Password sai → 401" "401" \
    -u "${WRONG_PASS}" "${API}/api/namespaces/default/deployments"

check_http "Username sai → 401" "401" \
    -u "${WRONG_USER}" "${API}/api/namespaces/default/deployments"

check_http "Auth header rong → 401" "401" \
    -H "Authorization: Basic " "${API}/api/namespaces/default/deployments"

check_http "Auth header khong hop le → 401" "401" \
    -H "Authorization: Bearer faketoken" "${API}/api/namespaces/default/deployments"

check_http "Auth Basic voi base64 sai → 401" "401" \
    -H "Authorization: Basic bm90YmFzZTY0ISE=" "${API}/api/namespaces/default/deployments"

# ----------------------------------------------------------
section "1.4 Dang nhap hop le"
# ----------------------------------------------------------

check_http "Dung credential → 200 deployments" "200" \
    -u "${VALID_AUTH}" "${API}/api/namespaces/default/deployments"

check_http "Dung credential → 200 policies" "200" \
    -u "${VALID_AUTH}" "${API}/api/namespaces/default/policies"

info "Kiem tra response body co dung JSON"
RESP=$(curl -s -u "${VALID_AUTH}" "${API}/api/namespaces/default/deployments")
if echo "$RESP" | python3 -m json.tool > /dev/null 2>&1; then
    pass "Response la JSON hop le"
else
    fail "Response khong phai JSON: $RESP"
fi

if echo "$RESP" | grep -q '"deployments"'; then
    pass "JSON chua truong 'deployments'"
else
    fail "JSON thieu truong 'deployments'"
fi

# ----------------------------------------------------------
section "1.5 Kiem tra WWW-Authenticate header"
# ----------------------------------------------------------

info "Kiem tra server tra header WWW-Authenticate khi bi tu choi"
HEADERS=$(curl -s -D - -o /dev/null "${API}/api/namespaces/default/deployments")
if echo "$HEADERS" | grep -qi "WWW-Authenticate"; then
    pass "Server tra header WWW-Authenticate (chuan RFC 7235)"
else
    fail "Server thieu header WWW-Authenticate"
fi

if echo "$HEADERS" | grep -qi 'realm="vArmor Console"'; then
    pass "WWW-Authenticate chua realm chinh xac"
else
    fail "WWW-Authenticate sai realm"
fi

# ----------------------------------------------------------
section "1.6 Kiem tra Content-Type JSON khi loi"
# ----------------------------------------------------------

CT=$(curl -s -D - -o /dev/null "${API}/api/namespaces/default/deployments" \
    | grep -i "content-type")
if echo "$CT" | grep -qi "application/json"; then
    pass "Loi 401 tra Content-Type: application/json"
else
    fail "Loi 401 khong tra Content-Type JSON: $CT"
fi

# ----------------------------------------------------------
echo -e "\n${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}KET QUA LAB 01:${NC}  ${GREEN}${PASSED} PASS${NC}  |  ${RED}${FAILED} FAIL${NC}  |  Tong: ${TOTAL}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}\n"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
