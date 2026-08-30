#!/usr/bin/env bash
#
# scripts/ci/sonar-findings.sh — Sonar quality-gate + findings read-back.
#
# Reads back what the quality:sonar job's `sonar.qualitygate.wait=true`
# upload produced: the gate verdict, every failing condition, open issues
# (worst severity first), and unreviewed security hotspots. Printed to the
# job log only — this script never fails the pipeline; gate pass/fail
# authority lives in the Sonar server and (advisorily) in quality:sonar
# itself.
#
# Five behaviors keep this diagnostic honest rather than misleading:
#
#   1. The quality-gate fetch IS the auth probe (one request, response
#      reused for both). An unauthenticated /api/issues/search returns HTTP
#      200 with an empty list — indistinguishable from a clean project — so
#      no findings list is printed unless this probe's HTTP status proved the
#      token was accepted. An auth failure is reported as an auth failure,
#      never silently as "no findings".
#   2. SonarQube accepts the token as a bearer header or as the basic-auth
#      username with an empty password, depending on server version: probe
#      bearer first, fall back to basic, then reuse whichever worked for
#      every later request.
#   3. Hotspots are a separate endpoint (/api/hotspots/search) — issues/search
#      never returns them. A non-200 there after a successful probe is a
#      token-permission answer (hotspot read is a separate grant), not a
#      credentials failure.
#   4. The project key comes from .scannerwork/report-task.txt (the
#      scanner's own record of what it just analyzed), never from
#      sonar-project.properties or $SONAR_PROJECT_KEY — both can drift from
#      what was actually uploaded.
#   5. A red gate with both lists empty still names the failing metric keys,
#      so there is always something to chase, never a bare "gate failed".
#
# A missing report-task.txt means the scanner did not run or died before
# upload; quality:sonar is allow_failure: true, so that is this job's normal
# companion on that branch, not an error condition — print one line and exit
# 0 rather than fail on an unresolvable path.
set -euo pipefail

REPORT_TASK_FILE=".scannerwork/report-task.txt"

if [[ ! -f "$REPORT_TASK_FILE" ]]; then
  echo "sonar-findings: no ${REPORT_TASK_FILE} — the scanner did not run or exited before upload; nothing to read back"
  exit 0
fi

# The `|| true` keeps a missing projectKey= line on the graceful exit-0 path
# below: under `set -e` a bare failing grep inside the substitution would
# abort the assignment itself and the -z guard would never run.
PROJECT_KEY=$({ grep -m1 '^projectKey=' "$REPORT_TASK_FILE" || true; } | cut -d= -f2-)
if [[ -z "$PROJECT_KEY" ]]; then
  echo "sonar-findings: ${REPORT_TASK_FILE} has no projectKey= line — cannot query Sonar" >&2
  exit 0
fi

RESP_FILE=$(mktemp)
trap 'rm -f "$RESP_FILE"' EXIT

sonar_curl() {
  # $1 = full URL, remaining args = extra curl options (e.g. --data-urlencode
  # pairs). Writes the response body to $RESP_FILE, prints the HTTP status
  # code (or "000" if curl itself failed, e.g. connection refused) — a
  # transport failure never kills the script under `set -e`.
  local url="$1"; shift
  local code
  if [[ "$AUTH_MODE" == bearer ]]; then
    code=$(curl -sS -G -o "$RESP_FILE" -w '%{http_code}' \
      -H "Authorization: Bearer ${SONAR_TOKEN}" "$@" "$url") || code="000"
  else
    code=$(curl -sS -G -o "$RESP_FILE" -w '%{http_code}' \
      -u "${SONAR_TOKEN}:" "$@" "$url") || code="000"
  fi
  printf '%s' "$code"
}

QG_URL="${SONAR_HOST_URL%/}/api/qualitygates/project_status"
HTTP_CODE="000"
for AUTH_MODE in bearer basic; do
  HTTP_CODE=$(sonar_curl "$QG_URL" --data-urlencode "projectKey=${PROJECT_KEY}")
  [[ "$HTTP_CODE" == "200" ]] && break
done

if [[ "$HTTP_CODE" != "200" ]]; then
  echo "sonar-findings: auth probe failed against ${SONAR_HOST_URL} — bearer and basic-auth token both rejected (last HTTP ${HTTP_CODE}); reporting an authentication failure, not \"no findings\"" >&2
  exit 0
fi

GATE_JSON=$(cat "$RESP_FILE")
GATE_STATUS=$(jq -r '.projectStatus.status // "UNKNOWN"' <<<"$GATE_JSON")
echo "=== Quality gate: ${GATE_STATUS} (${PROJECT_KEY}, auth: ${AUTH_MODE}) ==="

FAILED_CONDITIONS=$(jq -r '
  .projectStatus.conditions[]? | select(.status == "ERROR") |
  "\(.metricKey): \(.actualValue) \(.comparator) \(.errorThreshold)"
' <<<"$GATE_JSON")
if [[ -n "$FAILED_CONDITIONS" ]]; then
  echo "--- Failing conditions ---"
  echo "$FAILED_CONDITIONS"
fi

ISSUES_CODE=$(sonar_curl "${SONAR_HOST_URL%/}/api/issues/search" \
  --data-urlencode "componentKeys=${PROJECT_KEY}" \
  --data-urlencode "resolved=false" \
  --data-urlencode "s=SEVERITY" \
  --data-urlencode "asc=false" \
  --data-urlencode "ps=500")
ISSUE_COUNT=0
if [[ "$ISSUES_CODE" == "200" ]]; then
  ISSUES_JSON=$(cat "$RESP_FILE")
  ISSUE_COUNT=$(jq -r '.issues | length' <<<"$ISSUES_JSON")
  echo "--- Open issues: ${ISSUE_COUNT} ---"
  jq -r '.issues[]? | "[\(.severity)] \(.component):\(.line // "?") \(.rule) \(.message)"' <<<"$ISSUES_JSON"
else
  echo "sonar-findings: issues/search returned HTTP ${ISSUES_CODE} after a successful auth probe — treating as unreadable, not as zero issues" >&2
fi

HOTSPOTS_CODE=$(sonar_curl "${SONAR_HOST_URL%/}/api/hotspots/search" \
  --data-urlencode "projectKey=${PROJECT_KEY}" \
  --data-urlencode "status=TO_REVIEW" \
  --data-urlencode "ps=500")
HOTSPOT_COUNT=0
if [[ "$HOTSPOTS_CODE" == "200" ]]; then
  HOTSPOTS_JSON=$(cat "$RESP_FILE")
  HOTSPOT_COUNT=$(jq -r '.hotspots | length' <<<"$HOTSPOTS_JSON")
  echo "--- Unreviewed security hotspots: ${HOTSPOT_COUNT} ---"
  jq -r '.hotspots[]? | "[\(.vulnerabilityProbability)] \(.component):\(.line // "?") \(.message)"' <<<"$HOTSPOTS_JSON"
else
  echo "sonar-findings: hotspots/search returned HTTP ${HOTSPOTS_CODE} after a successful auth probe — a token-permission gap (hotspot read is a separate grant), not a credentials failure" >&2
fi

if [[ "$GATE_STATUS" == "ERROR" && "$ISSUE_COUNT" -eq 0 && "$HOTSPOT_COUNT" -eq 0 ]]; then
  FAILED_METRIC_KEYS=$(jq -r '.projectStatus.conditions[]? | select(.status == "ERROR") | .metricKey' <<<"$GATE_JSON" | paste -sd, -)
  echo "--- Gate failed with no listed issues/hotspots to explain it — chase these metric keys: ${FAILED_METRIC_KEYS} ---" >&2
fi

exit 0
