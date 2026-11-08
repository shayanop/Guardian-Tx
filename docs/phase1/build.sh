#!/usr/bin/env bash
# Build the Phase 1 PDF from Phase1_source.html.
#   ./build.sh                  final PDF  -> Phase1_GuardianTx_22I-0794.pdf
#   ./build.sh G1-06            final PDF with a project code -> Phase1_G1-06_22I-0794.pdf
#   ./build.sh --preview        draft with write boxes visible -> Phase1_PREVIEW.pdf
set -euo pipefail
cd "$(dirname "$0")"

HEAD_ROLL="22I-0794"
SRC="Phase1_source.html"
CODE=""

if [[ "${1:-}" == "--preview" ]]; then
  OUT="Phase1_PREVIEW.pdf"
else
  CODE="${1:-}"
  if [[ -n "$CODE" ]]; then
    [[ "$CODE" =~ ^G[123]-[0-9]+$ ]] || { echo "project code should look like G1-06"; exit 1; }
  fi
  left=$(grep -c 'class="write"' "$SRC" || true)
  unverified=$(grep -c 'class="verify"' "$SRC" || true)
  if (( left > 0 || unverified > 0 )); then
    echo "Not ready: $left write box(es) and $unverified unverified number(s) remain:"
    grep -n -B2 'class="write"' "$SRC" | grep -E '<h[23]>' | sed 's/<[^>]*>//g'
    grep -n 'class="verify"' "$SRC" | sed 's/<[^>]*>//g' | cut -c1-110
    exit 1
  fi
  OUT="Phase1_${CODE:-GuardianTx}_${HEAD_ROLL}.pdf"
fi

ROW=""
[[ -n "$CODE" ]] && ROW="<tr><td>Project code<\/td><td>${CODE}<\/td><\/tr>"

TMP=$(mktemp --suffix=.html -p .)
trap 'rm -f "$TMP"' EXIT
sed "s/{{PROJECT_CODE_ROW}}/${ROW}/" "$SRC" > "$TMP"
google-chrome --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer \
  --print-to-pdf="$OUT" "file://$PWD/$TMP" 2>/dev/null
echo "wrote $OUT ($(pdfinfo "$OUT" | awk '/Pages/ {print $2}') pages)"
