#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------------------------------- #
#                         by x41 and the praktikant  (v1.0)                     #
# ----------------------------------------------------------------------------- #

usage() {
  echo "Usage:"
  echo "  $0 <TARGET> [--udp] [--pn-fallback] [--stats-every <secs>]"
  echo "  $0 --iL <FILE> [--udp] [--pn-fallback] [--stats-every <secs>]"
  exit 1
}

# -----------------------------------------------------------------------------
# Root check (required for -sS / -sU / raw sockets)
# -----------------------------------------------------------------------------
if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] This script requires root privileges."
  echo "    Run it with: sudo $0 $*"
  exit 1
fi

if [[ $# -lt 1 ]]; then usage; fi

# -----------------------------------------------------------------------------
# Input parsing: either single TARGET or -iL/--iL <file>
# -----------------------------------------------------------------------------
INPUT_MODE="single"
TARGET=""
IL_FILE=""

if [[ "${1}" == "--iL" ]]; then
  [[ $# -ge 2 ]] || usage
  INPUT_MODE="il"
  IL_FILE="$2"
  shift 2
  [[ -f "${IL_FILE}" ]] || { echo "[!] --iL file not found: ${IL_FILE}"; exit 1; }
else
  TARGET="$1"
  shift
fi

# Flags
DO_UDP=0
PN_FALLBACK=0
STATS_EVERY="30s"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --udp) DO_UDP=1; shift ;;
    --pn-fallback) PN_FALLBACK=1; shift ;;
    --stats-every)
      [[ $# -ge 2 ]] || usage
      STATS_EVERY="$2"
      shift 2
      ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# Build target arguments for nmap
declare -a TARGET_ARG=()
if [[ "${INPUT_MODE}" == "il" ]]; then
  TARGET_ARG=(-iL "${IL_FILE}")
  DISPLAY_TARGET="iL:${IL_FILE}"
else
  TARGET_ARG=("${TARGET}")
  DISPLAY_TARGET="${TARGET}"
fi

# Performance defaults
MIN_RATE=500
MAX_RATE=1500
MIN_PAR=10
MAX_PAR=50
MAX_RETRIES=2
TIMING="-T4"

TS="$(date +%Y%m%d_%H%M%S)"

# OUTDIR naming: if -iL is used, include filename (sanitized) instead of raw targets
if [[ "${INPUT_MODE}" == "il" ]]; then
  SAFE_INPUT="$(basename "${IL_FILE}")"
else
  SAFE_INPUT="${DISPLAY_TARGET}"
fi

SAFE_INPUT="$(printf '%s' "${SAFE_INPUT}" | tr '/: ' '___' | tr -cd 'A-Za-z0-9._-')"
OUTDIR="nmap_${SAFE_INPUT}_${TS}"

# Directory layout
RESULTS_DIR="${OUTDIR}/results"
ADMIN_DIR="${OUTDIR}/admin"
LOGDIR="${ADMIN_DIR}/logs"
LISTDIR="${ADMIN_DIR}/lists"

mkdir -p "${RESULTS_DIR}" "${ADMIN_DIR}" "${LOGDIR}" "${LISTDIR}"

CMDLOG="${ADMIN_DIR}/cmdlog.txt"
SUMMARY_TXT="${ADMIN_DIR}/summary.txt"
SUMMARY_JSON="${ADMIN_DIR}/summary.json"

# Store "target descriptor" for reproducibility
{
  echo "mode=${INPUT_MODE}"
  echo "target=${DISPLAY_TARGET}"
  if [[ "${INPUT_MODE}" == "il" ]]; then
    echo "file=${IL_FILE}"
  fi
} > "${ADMIN_DIR}/target.txt"

echo "[*] OUTDIR : ${OUTDIR}"
echo "[*] TARGET : ${DISPLAY_TARGET}"
echo "[*] UDP    : $([[ "${DO_UDP}" -eq 1 ]] && echo "enabled" || echo "disabled")"
echo

log_cmd() { printf '%s\n' "$*" >> "${CMDLOG}"; }

# -----------------------------------------------------------------------------
# Console-clean nmap runner (START/END aligned, progress only)
# -----------------------------------------------------------------------------
run_nmap() {
  local phase="$1"
  local total_targets="$2"
  local logfile="$3"
  shift 3

  local -a cmd=( "$@" )
  : > "${logfile}"

  local joined=""
  printf -v joined '%q ' "${cmd[@]}"
  log_cmd "${joined} -> ${logfile}"

  printf '[*] START %s\n' "${phase}"

  local percent="?" etc="??:??" remaining="?:??:??"
  local elapsed="?:??:??" completed="?" up="?" left="?"
  local printed_progress=0

  while IFS= read -r line; do
    printf '%s\n' "${line}" >> "${logfile}"

    if [[ "${line}" == *"Timing: About"*"% done"* ]]; then
      percent="$(echo "${line}" | awk '{for(i=1;i<=NF;i++) if($i ~ /%/) {print $i; exit}}')"
      etc="$(echo "${line}" | awk -F"ETC: " '{print $2}' | awk '{print $1}')"
      remaining="$(echo "${line}" | awk -F"(" '{print $2}' | awk '{print $1}')"
    fi

    if [[ "${line}" == Stats:*elapsed*hosts*completed*up* ]]; then
      elapsed="$(echo "${line}" | awk '{print $2}')"
      completed="$(echo "${line}" | awk '{print $4}')"
      up="$(echo "${line}" | awk -F"(" '{print $2}' | awk '{print $1}')"

      if [[ "${total_targets}" =~ ^[0-9]+$ ]] && [[ "${completed}" =~ ^[0-9]+$ ]]; then
        (( total_targets >= completed )) && left="$(( total_targets - completed ))" || left="?"
      else
        left="?"
      fi

      printed_progress=1
      printf '\r[=] %s | %s | ETA %s | rem %s | done %s/%s | up %s | left %s | el %s' \
        "${phase}" "${percent}" "${etc}" "${remaining}" \
        "${completed}" "${total_targets}" "${up}" "${left}" "${elapsed}"
    fi
  done < <(stdbuf -oL -eL "${cmd[@]}" 2>&1 || true)

  [[ "${printed_progress}" -eq 1 ]] && echo
  printf '[*] END   %s (log: %s)\n\n' "${phase}" "${logfile}"
}

# -----------------------------------------------------------------------------
# Helpers: extract open TCP ports from gnmap to union + host map
# -----------------------------------------------------------------------------
extract_ports_from_gnmap() {
  local gnmap="$1"
  local union_file="$2"
  local map_csv="$3"

  [[ -s "${gnmap}" ]] || return 0

  awk -v union="${union_file}" -v csv="${map_csv}" '
    /^Host: / && $0 ~ /Ports: / {
      host=$2
      split($0, a, "Ports: ")
      split(a[2], b, "\t")
      ports_block=b[1]
      n=split(ports_block, p, ",")
      portlist=""
      for (i=1;i<=n;i++) {
        gsub(/^ +| +$/, "", p[i])
        split(p[i], f, "/")
        port=f[1]; state=f[2]; proto=f[3]
        if (proto=="tcp" && state=="open" && port~/^[0-9]+$/) {
          if (portlist=="") portlist=port
          else portlist=portlist "," port
          print port >> union
        }
      }
      if (portlist!="")
        print host "," "\"" portlist "\"" >> csv
    }
  ' "${gnmap}"
}

union_to_csv() {
  [[ -s "$1" ]] || return 0
  sort -n -u "$1" | paste -sd, -
}

# -----------------------------------------------------------------------------
# 00) Target enumeration (admin-only)
# -----------------------------------------------------------------------------
ALL_TARGETS="${LISTDIR}/all_targets.txt"
ENUM_GNMAP="${LISTDIR}/00_enum.gnmap"
ENUM_LOG="${LOGDIR}/00_enum.log"

run_nmap "00_enum" "?" "${ENUM_LOG}" \
  nmap -sL -n -oG "${ENUM_GNMAP}" "${TARGET_ARG[@]}"

awk '/^Host: /{print $2}' "${ENUM_GNMAP}" | sort -u > "${ALL_TARGETS}" || true
if [[ ! -s "${ALL_TARGETS}" ]]; then
  # If enumeration produced nothing, fall back to single display target
  printf '%s\n' "${DISPLAY_TARGET}" > "${ALL_TARGETS}"
fi
TOTAL_ALL="$(wc -l < "${ALL_TARGETS}" | tr -d ' ' 2>/dev/null || echo 0)"

# -----------------------------------------------------------------------------
# 01) Discovery TCP ping
# -----------------------------------------------------------------------------
DISC1_PREFIX="${RESULTS_DIR}/01_discovery_tcp_ping"
DISC1_LOG="${LOGDIR}/01_discovery_tcp_ping.log"

run_nmap "01_discovery" "${TOTAL_ALL}" "${DISC1_LOG}" \
  nmap -sn \
    -PS21,22,2222,25,80,110,111,135,139,143,161,443,445,8080,8443,993,995,1433,2049,3389,5900,5985 \
    -PA80,443,445,3389 \
    --reason \
    -n \
    ${TIMING} \
    --stats-every "${STATS_EVERY}" \
    -oA "${DISC1_PREFIX}" \
    "${TARGET_ARG[@]}"

ALIVE1="${LISTDIR}/alive_01_tcp_ping.txt"
if [[ -f "${DISC1_PREFIX}.gnmap" ]]; then
  awk '/Status: Up/{print $2}' "${DISC1_PREFIX}.gnmap" | sort -u > "${ALIVE1}" || true
else
  : > "${ALIVE1}"
fi

NOTALIVE1="${LISTDIR}/notalive_01_after_tcp_ping.txt"
comm -23 <(sort -u "${ALL_TARGETS}") <(sort -u "${ALIVE1}") > "${NOTALIVE1}" || true

ALIVE1_COUNT="$(wc -l < "${ALIVE1}" | tr -d ' ' 2>/dev/null || echo 0)"
NOTALIVE1_COUNT="$(wc -l < "${NOTALIVE1}" | tr -d ' ' 2>/dev/null || echo 0)"
echo "[*] Phase01 alive: ${ALIVE1_COUNT} | not-alive candidates: ${NOTALIVE1_COUNT}"
echo

# -----------------------------------------------------------------------------
# 02) ICMP retry only for not discovered
# -----------------------------------------------------------------------------
DISC2_PREFIX="${RESULTS_DIR}/02_discovery_icmp_retry"
DISC2_LOG="${LOGDIR}/02_discovery_icmp_retry.log"
ALIVE2="${LISTDIR}/alive_02_icmp_retry.txt"

if [[ -s "${NOTALIVE1}" ]]; then
  TOTAL_RETRY="$(wc -l < "${NOTALIVE1}" | tr -d ' ' 2>/dev/null || echo 0)"
  run_nmap "02_icmp_retry" "${TOTAL_RETRY}" "${DISC2_LOG}" \
    nmap -sn -PE -PP -PM \
      --reason \
      -n \
      ${TIMING} \
      --stats-every "${STATS_EVERY}" \
      -oA "${DISC2_PREFIX}" \
      -iL "${NOTALIVE1}"

  if [[ -f "${DISC2_PREFIX}.gnmap" ]]; then
    awk '/Status: Up/{print $2}' "${DISC2_PREFIX}.gnmap" | sort -u > "${ALIVE2}" || true
  else
    : > "${ALIVE2}"
  fi
else
  : > "${ALIVE2}"
fi

ALIVE_MERGED="${LISTDIR}/alive_merged_01_02.txt"
cat "${ALIVE1}" "${ALIVE2}" 2>/dev/null | sort -u > "${ALIVE_MERGED}" || true
ALIVE_MERGED_COUNT="$(wc -l < "${ALIVE_MERGED}" | tr -d ' ' 2>/dev/null || echo 0)"

NOTALIVE2="${LISTDIR}/notalive_02_after_icmp_retry.txt"
comm -23 <(sort -u "${ALL_TARGETS}") <(sort -u "${ALIVE_MERGED}") > "${NOTALIVE2}" || true
NOTALIVE2_COUNT="$(wc -l < "${NOTALIVE2}" | tr -d ' ' 2>/dev/null || echo 0)"

ALIVE2_COUNT="$(wc -l < "${ALIVE2}" | tr -d ' ' 2>/dev/null || echo 0)"
echo "[*] Phase02 alive: ${ALIVE2_COUNT} | alive merged: ${ALIVE_MERGED_COUNT} | not-alive candidates: ${NOTALIVE2_COUNT}"
echo

if [[ "${ALIVE_MERGED_COUNT}" -eq 0 && "${PN_FALLBACK}" -eq 0 ]]; then
  echo "[!] No hosts discovered (01+02). Aborting (enable --pn-fallback to continue)."
  exit 2
fi

# -----------------------------------------------------------------------------
# 03) TCP port-finding top5000 (important)
# -----------------------------------------------------------------------------
TCPFIND_PREFIX="${RESULTS_DIR}/03_tcp_ports_top5000"
TCPFIND_LOG="${LOGDIR}/03_tcp_ports_top5000.log"

if [[ "${ALIVE_MERGED_COUNT}" -gt 0 ]]; then
  run_nmap "03_tcp_ports" "${ALIVE_MERGED_COUNT}" "${TCPFIND_LOG}" \
    nmap -sS \
      --top-ports 5000 \
      --open --reason \
      --min-rate "${MIN_RATE}" \
      --max-rate "${MAX_RATE}" \
      --min-parallelism "${MIN_PAR}" \
      --max-parallelism "${MAX_PAR}" \
      --max-retries "${MAX_RETRIES}" \
      -n \
      ${TIMING} \
      --stats-every "${STATS_EVERY}" \
      -oA "${TCPFIND_PREFIX}" \
      -iL "${ALIVE_MERGED}"
else
  : > "${TCPFIND_PREFIX}.gnmap"
  : > "${TCPFIND_PREFIX}.xml"
  : > "${TCPFIND_PREFIX}.nmap"
fi

echo "[*] EyeWitness input XML: ${TCPFIND_PREFIX}.xml"
echo

# -----------------------------------------------------------------------------
# Optional: -Pn port-finding for not discovered
# -----------------------------------------------------------------------------
TCPFINDPN_PREFIX="${RESULTS_DIR}/03b_tcp_ports_top5000_pn_not_discovered"
TCPFINDPN_LOG="${LOGDIR}/03b_tcp_ports_top5000_pn_not_discovered.log"
DO_PN_PHASE=0

if [[ "${PN_FALLBACK}" -eq 1 && -s "${NOTALIVE2}" ]]; then
  DO_PN_PHASE=1
  TOTAL_PN="$(wc -l < "${NOTALIVE2}" | tr -d ' ' 2>/dev/null || echo 0)"

  run_nmap "03b_tcp_ports_pn" "${TOTAL_PN}" "${TCPFINDPN_LOG}" \
    nmap -sS \
      --top-ports 5000 \
      -Pn \
      --open --reason \
      --min-rate "${MIN_RATE}" \
      --max-rate "${MAX_RATE}" \
      --min-parallelism "${MIN_PAR}" \
      --max-parallelism "${MAX_PAR}" \
      --max-retries "${MAX_RETRIES}" \
      -system-dns \
      ${TIMING} \
      --stats-every "${STATS_EVERY}" \
      -oA "${TCPFINDPN_PREFIX}" \
      -iL "${NOTALIVE2}"

  echo "[*] EyeWitness input XML (Pn): ${TCPFINDPN_PREFIX}.xml"
  echo
else
  : > "${TCPFINDPN_PREFIX}.gnmap"
  : > "${TCPFINDPN_PREFIX}.xml"
  : > "${TCPFINDPN_PREFIX}.nmap"
fi

# -----------------------------------------------------------------------------
# Extract ports (03 + optional 03b) -> union + host map
# -----------------------------------------------------------------------------
UNION_FILE="${LISTDIR}/union_ports_top5000.txt"
PORTMAP="${LISTDIR}/open_ports_map_top5000.csv"
HOSTS_WITH_PORTS="${LISTDIR}/hosts_with_open_ports_top5000.txt"

: > "${UNION_FILE}"
echo "host,ports" > "${PORTMAP}"

extract_ports_from_gnmap "${TCPFIND_PREFIX}.gnmap" "${UNION_FILE}" "${PORTMAP}"
if [[ "${DO_PN_PHASE}" -eq 1 ]]; then
  extract_ports_from_gnmap "${TCPFINDPN_PREFIX}.gnmap" "${UNION_FILE}" "${PORTMAP}"
fi

UNION_PORTS="$(union_to_csv "${UNION_FILE}" || true)"
awk -F, 'NR>1{print $1}' "${PORTMAP}" | sort -u > "${HOSTS_WITH_PORTS}" || true
HOSTS_WITH_PORTS_COUNT="$(wc -l < "${HOSTS_WITH_PORTS}" | tr -d ' ' 2>/dev/null || echo 0)"
UNION_COUNT="$(sort -n -u "${UNION_FILE}" 2>/dev/null | wc -l | tr -d ' ' 2>/dev/null || echo 0)"

echo "[*] Hosts with open TCP ports: ${HOSTS_WITH_PORTS_COUNT}"
echo "[*] Union port count          : ${UNION_COUNT}"
echo

# -----------------------------------------------------------------------------
# 04) Targeted -sV -sC (important) - single oA, union ports, filtered to open
# -----------------------------------------------------------------------------
TARGETED_PREFIX="${RESULTS_DIR}/04_tcp_targeted_sV_sC"
TARGETED_LOG="${LOGDIR}/04_tcp_targeted_sV_sC.log"

if [[ "${HOSTS_WITH_PORTS_COUNT}" -gt 0 && -n "${UNION_PORTS}" ]]; then
  echo "[*] Starting targeted -sV -sC (union ports, --open)"
  echo "[*] Targeted output XML: ${TARGETED_PREFIX}.xml"
  echo

  run_nmap "04_targeted" "${HOSTS_WITH_PORTS_COUNT}" "${TARGETED_LOG}" \
    nmap -sS \
      -sV -sC \
      -p "${UNION_PORTS}" \
      --open --reason \
      --min-rate "${MIN_RATE}" \
      --max-rate "${MAX_RATE}" \
      --min-parallelism "${MIN_PAR}" \
      --max-parallelism "${MAX_PAR}" \
      --max-retries "${MAX_RETRIES}" \
      --system-dns \
      ${TIMING} \
      --stats-every "${STATS_EVERY}" \
      -oA "${TARGETED_PREFIX}" \
      -iL "${HOSTS_WITH_PORTS}"
fi

# -----------------------------------------------------------------------------
# 05) Optional UDP top200
# -----------------------------------------------------------------------------
if [[ "${DO_UDP}" -eq 1 && "${ALIVE_MERGED_COUNT}" -gt 0 ]]; then
  UDP_PREFIX="${RESULTS_DIR}/05_udp_top200"
  UDP_LOG="${LOGDIR}/05_udp_top200.log"

  run_nmap "05_udp_top200" "${ALIVE_MERGED_COUNT}" "${UDP_LOG}" \
    nmap -sU \
      --top-ports 200 \
      --reason \
      --min-rate "${MIN_RATE}" \
      --max-rate "${MAX_RATE}" \
      --min-parallelism "${MIN_PAR}" \
      --max-parallelism "${MAX_PAR}" \
      --max-retries 1 \
      -n \
      ${TIMING} \
      --stats-every "${STATS_EVERY}" \
      -oA "${UDP_PREFIX}" \
      -iL "${ALIVE_MERGED}"
fi

# -----------------------------------------------------------------------------
# Admin combined text outputs + summary
# -----------------------------------------------------------------------------
COMBINED_GNMAP="${ADMIN_DIR}/combined.gnmap"
COMBINED_NMAP="${ADMIN_DIR}/combined.nmap"
: > "${COMBINED_GNMAP}"
: > "${COMBINED_NMAP}"

for f in \
  "${DISC1_PREFIX}.gnmap" \
  "${DISC2_PREFIX}.gnmap" \
  "${TCPFIND_PREFIX}.gnmap" \
  "${TCPFINDPN_PREFIX}.gnmap" \
  "${TARGETED_PREFIX}.gnmap" \
  "${RESULTS_DIR}/05_udp_top200.gnmap"
do
  [[ -f "${f}" ]] && cat "${f}" >> "${COMBINED_GNMAP}"
done

for f in \
  "${DISC1_PREFIX}.nmap" \
  "${DISC2_PREFIX}.nmap" \
  "${TCPFIND_PREFIX}.nmap" \
  "${TCPFINDPN_PREFIX}.nmap" \
  "${TARGETED_PREFIX}.nmap" \
  "${RESULTS_DIR}/05_udp_top200.nmap"
do
  [[ -f "${f}" ]] && cat "${f}" >> "${COMBINED_NMAP}"
done

{
  echo "=== Nmap Overview Summary ==="
  echo "Target: ${DISPLAY_TARGET}"
  echo "Timestamp: ${TS}"
  echo
  echo "--- Key outputs ---"
  echo "Phase03 TCP ports (EyeWitness XML): ${TCPFIND_PREFIX}.xml"
  if [[ "${DO_PN_PHASE}" -eq 1 ]]; then
    echo "Phase03b TCP ports Pn XML        : ${TCPFINDPN_PREFIX}.xml"
  fi
  if [[ -f "${TARGETED_PREFIX}.xml" ]]; then
    echo "Phase04 Targeted sV/sC XML       : ${TARGETED_PREFIX}.xml"
  fi
  if [[ "${DO_UDP}" -eq 1 && -f "${RESULTS_DIR}/05_udp_top200.xml" ]]; then
    echo "Phase05 UDP top200 XML           : ${RESULTS_DIR}/05_udp_top200.xml"
  fi
  echo
  echo "--- Counts ---"
  echo "All targets enumerated           : ${TOTAL_ALL}"
  echo "Alive (TCP ping)                 : ${ALIVE1_COUNT}"
  echo "Alive (ICMP retry)               : ${ALIVE2_COUNT}"
  echo "Alive (merged)                   : ${ALIVE_MERGED_COUNT}"
  echo "Not-alive candidates after retry : ${NOTALIVE2_COUNT}"
  echo "Hosts with open TCP ports        : ${HOSTS_WITH_PORTS_COUNT}"
  echo "Union port count (top5000)       : ${UNION_COUNT}"
  echo
  echo "--- Locations ---"
  echo "Scan results                     : ${RESULTS_DIR}/"
  echo "Administrative/debug             : ${ADMIN_DIR}/"
  echo "Nmap full logs per phase         : ${LOGDIR}/"
} > "${SUMMARY_TXT}"

cat > "${SUMMARY_JSON}" <<EOF
{
  "target": "$(printf '%s' "${DISPLAY_TARGET}" | sed 's/"/\\"/g')",
  "timestamp": "${TS}",
  "flags": {
    "udp": ${DO_UDP},
    "pn_fallback": ${PN_FALLBACK},
    "input_mode": "$(printf '%s' "${INPUT_MODE}" | sed 's/"/\\"/g')"
  },
  "counts": {
    "all_targets_enumerated": ${TOTAL_ALL},
    "alive_tcp_ping": ${ALIVE1_COUNT},
    "alive_icmp_retry": ${ALIVE2_COUNT},
    "alive_merged": ${ALIVE_MERGED_COUNT},
    "not_alive_candidates_after_retry": ${NOTALIVE2_COUNT},
    "hosts_with_open_tcp_ports": ${HOSTS_WITH_PORTS_COUNT},
    "union_top5000_port_count": ${UNION_COUNT}
  },
  "paths": {
    "results_dir": "results/",
    "admin_dir": "admin/",
    "cmdlog": "admin/cmdlog.txt",
    "summary_txt": "admin/summary.txt",
    "summary_json": "admin/summary.json",
    "eyewitness_xml": "results/03_tcp_ports_top5000.xml",
    "targeted_xml": "results/04_tcp_targeted_sV_sC.xml"
  }
}
EOF

echo "[*] Scan complete."
echo "[*] Results  : ${RESULTS_DIR}/"
echo "[*] Summary  : ${SUMMARY_TXT}"
echo "[*] Cmdlog   : ${CMDLOG}"
echo "[*] Logs     : ${LOGDIR}/"
