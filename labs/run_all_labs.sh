#!/bin/bash
# ============================================================
# MASTER TEST RUNNER — Chay toan bo 7 Lab
# Su dung: bash /opt/armor-pilot/labs/run_all_labs.sh
# ============================================================

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARMORPILOT_API_URL="${ARMORPILOT_API_URL:-http://127.0.0.1:30080}"
ARMORPILOT_USERNAME="${ARMORPILOT_USERNAME:-admin}"
: "${ARMORPILOT_PASSWORD:?Set ARMORPILOT_PASSWORD before running the lab suite}"
export ARMORPILOT_API_URL ARMORPILOT_USERNAME ARMORPILOT_PASSWORD

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_SKIP=0
declare -A LAB_RESULTS

LABS=(
    "lab01_auth.sh:LAB 01 - Xac thuc & Bao mat"
    "lab02_deployments.sh:LAB 02 - Phat hien Deployment"
    "lab03_policies.sh:LAB 03 - Vong doi Policy (CRUD)"
    "lab04_banned_files.sh:LAB 04 - Chan file nhay cam"
    "lab05_escape_prevention.sh:LAB 05 - Ngan Container Escape"
    "lab06_audit_logs.sh:LAB 06 - Kiem tra Audit Log"
    "lab07_rbac.sh:LAB 07 - Xac minh RBAC"
)

print_banner() {
    echo -e "\n${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║          ArmorPilot — MASTER TEST SUITE                 ║"
    echo "║          Thoi gian: $(date '+%Y-%m-%d %H:%M:%S')                     ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_separator() {
    echo -e "\n${BLUE}$(printf '═%.0s' {1..62})${NC}\n"
}

run_lab() {
    local file="$1" label="$2"
    local log_file="/tmp/varmor_lab_$(echo "${file}" | tr '.' '_').log"

    echo -e "\n${BOLD}${YELLOW}> CHAY: ${label}${NC}"
    echo -e "${BLUE}  File: ${LAB_DIR}/${file}${NC}"

    # Chay lab, luu ra file (tranh subshell voi pipe)
    bash "${LAB_DIR}/${file}" > "${log_file}" 2>&1
    local exit_code=$?

    # In ket qua
    cat "${log_file}"

    # Dem ket qua (strip newlines)
    local lab_pass lab_fail lab_skip
    lab_pass=$(grep -c '\[PASS\]' "${log_file}" 2>/dev/null); lab_pass=${lab_pass:-0}
    lab_fail=$(grep -c '\[FAIL\]' "${log_file}" 2>/dev/null); lab_fail=${lab_fail:-0}
    lab_skip=$(grep -c '\[SKIP\]' "${log_file}" 2>/dev/null); lab_skip=${lab_skip:-0}

    TOTAL_PASS=$(( TOTAL_PASS + lab_pass ))
    TOTAL_FAIL=$(( TOTAL_FAIL + lab_fail ))
    TOTAL_SKIP=$(( TOTAL_SKIP + lab_skip ))

    if [ "${exit_code}" -eq 0 ]; then
        LAB_RESULTS["${label}"]="PASS"
        echo -e "  ${GREEN}> ${label}: HOAN THANH (${lab_pass} pass, ${lab_skip} skip)${NC}"
    else
        LAB_RESULTS["${label}"]="FAIL"
        echo -e "  ${RED}> ${label}: CO LOI (${lab_fail} fail)${NC}"
    fi
}

# ── Pre-flight checks ──────────────────────────────────────────
preflight() {
    echo -e "\n${CYAN}${BOLD}=== KIEM TRA TIEN QUYET ===${NC}"
    local ok=true

    # curl
    if command -v curl > /dev/null 2>&1; then
        echo -e "  ${GREEN}[OK]${NC} curl co san"
    else
        echo -e "  ${RED}[FAIL]${NC} curl khong co — cai dat bang: apt-get install -y curl"
        ok=false
    fi

    # kubectl
    if command -v kubectl > /dev/null 2>&1; then
        echo -e "  ${GREEN}[OK]${NC} kubectl co san: $(kubectl version --client --short 2>/dev/null)"
    else
        echo -e "  ${RED}[FAIL]${NC} kubectl khong co"
        ok=false
    fi

    # Console API accessible
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${ARMORPILOT_API_URL}/" 2>/dev/null)
    if [ "${HTTP_CODE}" = "200" ]; then
        echo -e "  ${GREEN}[OK]${NC} Console API hoat dong (HTTP 200)"
    else
        echo -e "  ${RED}[FAIL]${NC} Console API khong hoat dong (HTTP ${HTTP_CODE})"
        echo -e "        Chay: systemctl restart armor-pilot-pf"
        ok=false
    fi

    # Auth working
    AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${ARMORPILOT_USERNAME}:${ARMORPILOT_PASSWORD}" \
        "${ARMORPILOT_API_URL}/api/namespaces/default/deployments" 2>/dev/null)
    if [ "${AUTH_CODE}" = "200" ]; then
        echo -e "  ${GREEN}[OK]${NC} Xac thuc admin hoat dong"
    else
        echo -e "  ${RED}[FAIL]${NC} Xac thuc admin that bai (HTTP ${AUTH_CODE})"
        ok=false
    fi

    # varmor-agent check
    AGENT_STATUS=$(kubectl get pods -n varmor -l app=varmor-agent \
        -o jsonpath='{.items[0].status.phase}' 2>/dev/null)
    if [ "${AGENT_STATUS}" = "Running" ]; then
        echo -e "  ${GREEN}[OK]${NC} varmor-agent: Running"
    else
        echo -e "  ${YELLOW}[WARN]${NC} varmor-agent: ${AGENT_STATUS:-not found}"
        echo -e "         (Lab 04 & 05 se skip kiem tra thuc thi kernel)"
    fi

    echo ""
    [ "$ok" = "true" ] && return 0 || return 1
}

# ── Main ───────────────────────────────────────────────────────
print_banner

if ! preflight; then
    echo -e "${RED}${BOLD}Tien quyet khong du — dung test suite.${NC}"
    exit 1
fi

# Chay tung lab
if [ "$1" = "--lab" ] && [ -n "$2" ]; then
    # Che do chay lab cu the: ./run_all_labs.sh --lab 03
    LAB_NUM=$(printf "%02d" "$2")
    LAB_FILE="lab${LAB_NUM}_"*
    FULL_PATH="${LAB_DIR}/lab${LAB_NUM}_"*
    if ls ${FULL_PATH} > /dev/null 2>&1; then
        for f in ${FULL_PATH}; do
            label="LAB ${LAB_NUM}"
            run_lab "$(basename $f)" "${label}"
        done
    else
        echo -e "${RED}Khong tim thay lab ${LAB_NUM}${NC}"
        exit 1
    fi
else
    # Chay tat ca
    for entry in "${LABS[@]}"; do
        IFS=':' read -r file label <<< "$entry"
        print_separator
        run_lab "${file}" "${label}"
    done
fi

# ── Final Report ───────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    BAO CAO TONG HOP                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  %-58s ║\n" "Thoi gian: $(date '+%Y-%m-%d %H:%M:%S')"
echo "╠══════════════════════════════════════════════════════════════╣"

for entry in "${LABS[@]}"; do
    IFS=':' read -r file label <<< "$entry"
    result="${LAB_RESULTS[$label]:-N/A}"
    if [ "$result" = "PASS" ]; then
        printf "║  ${GREEN}%-58s${CYAN} ║\n" "✔ ${label}"
    elif [ "$result" = "FAIL" ]; then
        printf "║  ${RED}%-58s${CYAN} ║\n" "✘ ${label}"
    else
        printf "║  ${YELLOW}%-58s${CYAN} ║\n" "○ ${label} (skipped)"
    fi
done

echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  ${GREEN}PASS: %-4d${CYAN}  ${RED}FAIL: %-4d${CYAN}  ${YELLOW}SKIP: %-4d${CYAN}  Tong: %-14d ║\n" \
    "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP" "$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ "$TOTAL_FAIL" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}TAT CA LAB HOAN THANH THANH CONG!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}CO ${TOTAL_FAIL} TEST THAT BAI — Kiem tra log o tren de khac phuc.${NC}"
    exit 1
fi
