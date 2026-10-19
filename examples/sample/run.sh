#!/usr/bin/env sh
# Runs the sample review and checks the result. Usage: examples/sample/run.sh [path-to-rv-hashinv]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=${1:-rv-hashinv}
out="$here/out"
"$bin" self-test
# Expected exit code 0: one medium finding (extension mismatch) and one duplicate pair, no high finding.
"$bin" scan --input "$here/evidence" --hash sha256,md5 --lang all --case DEMO-001 --actor "Sample" --out "$out" --progress none
run=$(ls "$out/logs" | tail -n 1)
"$bin" verify-log "$out/logs/$run"
echo "Reports: $out/reports/$run/statistics.en.html"
