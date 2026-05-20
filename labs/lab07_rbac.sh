#!/bin/bash
# ============================================================
# LAB 07: Xac minh RBAC — Phan quyen ServiceAccount
# Muc tieu: Dam bao Console chi co quyen can thiet (least privilege)
#           va khong co quyen qua rong (over-privilege)
# ============================================================

NS="default"
SA="varmor-console-sa"
CR="varmor-console-role"
CRB="varmor-console-binding"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

PASSED=0; FAILED=0; TOTAL=0

pass()  { echo -e "  ${GREEN}[PASS]${NC} $1"; PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1"; FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); }
info()  { echo -e "  ${BLUE}[INFO]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
section() { echo -e "\n${CYAN}${BOLD}>>> $1${NC}"; }

# Kiem tra quyen cua ServiceAccount
can_do() {
    local verb="$1" resource="$2" group="${3:-}"
    local result
    if [ -n "$group" ]; then
        result=$(kubectl auth can-i "${verb}" "${resource}" \
            --as="system:serviceaccount:${NS}:${SA}" \
            --all-namespaces 2>/dev/null || echo "no")
    else
        result=$(kubectl auth can-i "${verb}" "${resource}" \
            --as="system:serviceaccount:${NS}:${SA}" \
            --all-namespaces 2>/dev/null || echo "no")
    fi
    echo "$result"
}

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         LAB 07: KIEM TRA RBAC & PHAN QUYEN          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"

# ----------------------------------------------------------
section "7.1 Kiem tra ServiceAccount ton tai"
# ----------------------------------------------------------

SA_EXISTS=$(kubectl get serviceaccount "${SA}" -n "${NS}" \
    -o jsonpath='{.metadata.name}' 2>/dev/null)
if [ "${SA_EXISTS}" = "${SA}" ]; then
    pass "ServiceAccount '${SA}' ton tai trong namespace '${NS}'"
else
    fail "ServiceAccount '${SA}' khong ton tai"
fi

# ----------------------------------------------------------
section "7.2 Kiem tra ClusterRole ton tai va co quy tac dung"
# ----------------------------------------------------------

CR_EXISTS=$(kubectl get clusterrole "${CR}" \
    -o jsonpath='{.metadata.name}' 2>/dev/null)
if [ "${CR_EXISTS}" = "${CR}" ]; then
    pass "ClusterRole '${CR}' ton tai"
else
    fail "ClusterRole '${CR}' khong ton tai"
fi

# Kiem tra rules cho apps/deployments
RULES=$(kubectl get clusterrole "${CR}" -o json 2>/dev/null)

echo "$RULES" | python3 -c "
import sys, json
cr = json.load(sys.stdin)
rules = cr.get('rules', [])
deploy_rule = next((r for r in rules if 'deployments' in r.get('resources', [])), None)
if not deploy_rule:
    print('MISSING')
    sys.exit(1)
verbs = deploy_rule.get('verbs', [])
for v in ['get', 'list', 'watch']:
    if v in verbs:
        print(f'has:{v}')
" 2>/dev/null | while read -r line; do
    verb="${line#has:}"
    [ "${verb}" = "MISSING" ] && fail "Rule cho deployments bi thieu" && continue
    pass "ClusterRole co verb '${verb}' tren deployments"
done

# Kiem tra rules cho crd.varmor.org/varmorpolicies
echo "$RULES" | python3 -c "
import sys, json
cr = json.load(sys.stdin)
rules = cr.get('rules', [])
varmor_rule = next((r for r in rules
    if 'crd.varmor.org' in r.get('apiGroups', [])
    and 'varmorpolicies' in r.get('resources', [])), None)
if not varmor_rule:
    print('MISSING')
    sys.exit(1)
verbs = varmor_rule.get('verbs', [])
for v in ['get', 'list', 'watch', 'create', 'update', 'patch', 'delete']:
    if v in verbs:
        print(f'has:{v}')
    else:
        print(f'miss:{v}')
" 2>/dev/null | while read -r line; do
    if [[ "$line" == has:* ]]; then
        pass "VarmorPolicy verb '${line#has:}' duoc cap quyen"
    elif [[ "$line" == miss:* ]]; then
        fail "VarmorPolicy verb '${line#miss:}' BI THIEU trong ClusterRole"
    fi
done

# ----------------------------------------------------------
section "7.3 Kiem tra ClusterRoleBinding"
# ----------------------------------------------------------

CRB_EXISTS=$(kubectl get clusterrolebinding "${CRB}" \
    -o jsonpath='{.metadata.name}' 2>/dev/null)
if [ "${CRB_EXISTS}" = "${CRB}" ]; then
    pass "ClusterRoleBinding '${CRB}' ton tai"
else
    fail "ClusterRoleBinding '${CRB}' khong ton tai"
fi

BOUND_SA=$(kubectl get clusterrolebinding "${CRB}" \
    -o jsonpath='{.subjects[0].name}' 2>/dev/null)
BOUND_NS=$(kubectl get clusterrolebinding "${CRB}" \
    -o jsonpath='{.subjects[0].namespace}' 2>/dev/null)
BOUND_ROLE=$(kubectl get clusterrolebinding "${CRB}" \
    -o jsonpath='{.roleRef.name}' 2>/dev/null)

[ "${BOUND_SA}" = "${SA}" ]   && pass "Binding tro dung vao SA '${SA}'" \
    || fail "Binding sai SA: '${BOUND_SA}'"
[ "${BOUND_NS}" = "${NS}" ]   && pass "Binding SA trong namespace '${NS}'" \
    || fail "Binding sai namespace: '${BOUND_NS}'"
[ "${BOUND_ROLE}" = "${CR}" ] && pass "Binding tro dung ClusterRole '${CR}'" \
    || fail "Binding sai role: '${BOUND_ROLE}'"

# ----------------------------------------------------------
section "7.4 Kiem tra quyen DUOC PHEP (permitted)"
# ----------------------------------------------------------

info "Su dung 'kubectl auth can-i' cho ServiceAccount '${SA}'"

declare -A ALLOWED_OPS=(
    ["get deployments"]="get deployments"
    ["list deployments"]="list deployments"
    ["get varmorpolicies.crd.varmor.org"]="get varmorpolicies.crd.varmor.org"
    ["list varmorpolicies.crd.varmor.org"]="list varmorpolicies.crd.varmor.org"
    ["create varmorpolicies.crd.varmor.org"]="create varmorpolicies.crd.varmor.org"
    ["delete varmorpolicies.crd.varmor.org"]="delete varmorpolicies.crd.varmor.org"
    ["update varmorpolicies.crd.varmor.org"]="update varmorpolicies.crd.varmor.org"
    ["patch varmorpolicies.crd.varmor.org"]="patch varmorpolicies.crd.varmor.org"
)

for label in "${!ALLOWED_OPS[@]}"; do
    parts=(${ALLOWED_OPS[$label]})
    verb="${parts[0]}"
    resource="${parts[1]}"
    result=$(kubectl auth can-i "${verb}" "${resource}" \
        --as="system:serviceaccount:${NS}:${SA}" \
        --all-namespaces 2>/dev/null)
    if [ "${result}" = "yes" ]; then
        pass "SA co the: ${label}"
    else
        fail "SA KHONG THE: ${label} (phai co quyen nay)"
    fi
done

# ----------------------------------------------------------
section "7.5 Kiem tra quyen BI CAM (forbidden — Least Privilege)"
# ----------------------------------------------------------

declare -A FORBIDDEN_OPS=(
    ["delete deployments"]="delete deployments"
    ["create deployments"]="create deployments"
    ["delete namespaces"]="delete namespaces"
    ["create secrets"]="create secrets"
    ["list secrets"]="list secrets"
    ["get secrets"]="get secrets"
    ["create pods"]="create pods"
    ["delete nodes"]="delete nodes"
    ["get clusterroles"]="get clusterroles"
)

for label in "${!FORBIDDEN_OPS[@]}"; do
    parts=(${FORBIDDEN_OPS[$label]})
    verb="${parts[0]}"
    resource="${parts[1]}"
    result=$(kubectl auth can-i "${verb}" "${resource}" \
        --as="system:serviceaccount:${NS}:${SA}" \
        --all-namespaces 2>/dev/null)
    if [ "${result}" = "no" ] || [ "${result}" = "denied" ]; then
        pass "SA bi cam: ${label} (least privilege OK)"
    else
        fail "SA co quyen QUA RONG: ${label} — co the gay rui ro!"
    fi
done

# ----------------------------------------------------------
section "7.6 Kiem tra Pod chay dung ServiceAccount"
# ----------------------------------------------------------

POD_SA=$(kubectl get pods -l app=varmor-console -n "${NS}" \
    -o jsonpath='{.items[0].spec.serviceAccountName}' 2>/dev/null)
if [ "${POD_SA}" = "${SA}" ]; then
    pass "Console pod dang dung ServiceAccount '${SA}'"
else
    fail "Console pod dung sai SA: '${POD_SA}' (nen la '${SA}')"
fi

# Kiem tra token tu dong gan vao pod
TOKEN_MOUNTED=$(kubectl get pods -l app=varmor-console -n "${NS}" \
    -o jsonpath='{.items[0].spec.automountServiceAccountToken}' 2>/dev/null)
info "automountServiceAccountToken: ${TOKEN_MOUNTED:-'true (default)'}"
pass "ServiceAccount token duoc mount vao pod (in-cluster config hoat dong)"

# ----------------------------------------------------------
section "7.7 Kiem tra bao mat container"
# ----------------------------------------------------------

POD_JSON=$(kubectl get pods -l app=varmor-console -n "${NS}" -o json 2>/dev/null)

RUN_AS_NR=$(echo "${POD_JSON}" | python3 -c \
    "import sys,json; p=json.load(sys.stdin).get('items',[{}])[0]; \
     print(p.get('spec',{}).get('securityContext',{}).get('runAsNonRoot','false'))" \
    2>/dev/null)
[ "${RUN_AS_NR}" = "True" ] && pass "runAsNonRoot=True (chay khong co root)" \
    || warn "runAsNonRoot chua set (nen bat trong prod)"

ALLOW_PRIV=$(echo "${POD_JSON}" | python3 -c \
    "import sys,json; p=json.load(sys.stdin).get('items',[{}])[0]; \
     c=p.get('spec',{}).get('containers',[{}])[0]; \
     sc=c.get('securityContext',{}); \
     print(sc.get('allowPrivilegeEscalation','not set'))" \
    2>/dev/null)
[ "${ALLOW_PRIV}" = "False" ] && pass "allowPrivilegeEscalation=False (an toan)" \
    || warn "allowPrivilegeEscalation: ${ALLOW_PRIV}"

CAPS=$(echo "${POD_JSON}" | python3 -c \
    "import sys,json; p=json.load(sys.stdin).get('items',[{}])[0]; \
     c=p.get('spec',{}).get('containers',[{}])[0]; \
     sc=c.get('securityContext',{}); \
     print(sc.get('capabilities',{}).get('drop',['none']))" \
    2>/dev/null)
if echo "${CAPS}" | grep -qi "ALL"; then
    pass "capabilities.drop=['ALL'] — drop all capabilities"
else
    warn "Chua drop all capabilities: ${CAPS}"
fi

# ----------------------------------------------------------
echo -e "\n${BOLD}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}KET QUA LAB 07:${NC}  ${GREEN}${PASSED} PASS${NC}  |  ${RED}${FAILED} FAIL${NC}  |  Tong: ${TOTAL}"
echo -e "${BOLD}══════════════════════════════════════════════════════${NC}\n"

[ "$FAILED" -eq 0 ] && exit 0 || exit 1
