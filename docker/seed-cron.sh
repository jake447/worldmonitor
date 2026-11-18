#!/bin/sh
# Railway cron wrapper for the seeders (every 30 min). A full scripts/run-seeders.sh
# pass takes over two hours, and Railway starts the next cron run on schedule, so an
# alphabetical pass was cut off at the same place every time and never reached the
# map layers (earthquakes, military flights, weather). This runs the map-layer
# seeders first, then the rest from a start point that rotates every run, and stops
# starting new seeders once the time budget is spent so each run ends before the next.
cd "$(dirname "$0")/.." || exit 1
BUDGET="${SEED_BUDGET_SECONDS:-1500}"   # seconds of a 30-minute slot to spend
PER="${SEED_TIMEOUT:-300}"              # cap for one seeder
BUNDLE_PER="${SEED_BUNDLE_TIMEOUT:-600}" # bundles run many sources inside
STEP="${SEED_ROTATE_STEP:-40}"          # how far the start point moves each run
PRIORITY="earthquakes military-flights weather-alerts natural-events conflict-intel ucdp-events unrest-events fire-detections internet-outages cyber-threats security-advisories sanctions-pressure climate-disasters displacement-summary insights military-maritime-news"
start=$(date +%s); ok=0; fail=0; ran=0
remaining() { echo $(( BUDGET - ($(date +%s) - start) )); }
run() {
  cap=$PER; case "$1" in bundle-*) cap=$BUNDLE_PER;; esac
  r=$(remaining); [ "$r" -le 0 ] && return 1
  [ "$cap" -gt $((r + 60)) ] && cap=$((r + 60))
  out=$(timeout -k 15 "$cap" node "scripts/seed-$1.mjs" 2>&1); rc=$?
  ran=$((ran + 1)); if [ "$rc" -eq 0 ]; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
  echo "→ seed-$1.mjs rc=$rc $(printf '%s' "$out" | tail -1 | cut -c1-160)"
}
for n in $PRIORITY; do [ -f "scripts/seed-$n.mjs" ] && { run "$n" || break; }; done
pf=$(mktemp); echo $PRIORITY | tr ' ' '\n' > "$pf"
rest=$(ls scripts/seed-*.mjs | sed 's#^scripts/seed-##; s#\.mjs$##' | grep -vxF -f "$pf"); rm -f "$pf"
total=$(printf '%s\n' "$rest" | grep -c .)
offset=$(( ($(date +%s) / 1800 * STEP) % (total > 0 ? total : 1) ))
order=$(printf '%s\n' "$rest" | tail -n +$((offset + 1)))
[ "$offset" -gt 0 ] && order="$order
$(printf '%s\n' "$rest" | head -n "$offset")"
i=0
for n in $order; do
  [ "$(remaining)" -le 0 ] && break
  run "$n" || break
  i=$((i + 1))
done
echo "Done: $ran ran, $ok ok, $fail failed, priority first, then $i of $total others from #$offset, $(( $(date +%s) - start ))s"
