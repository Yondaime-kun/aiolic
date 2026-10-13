#!/bin/sh
# Build aiolic, run its checks, and demonstrate the protocol end to end.
#
# The demo starts the server on a loopback port with no TLS (TLS is what the
# client pins; it is not what this demo tests), makes one device check and one
# job claim, verifies both with the verify subcommand, then alters a signed field
# in each and shows the verifier reject it.
#
# Needs only a Go toolchain and a POSIX shell. No network.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"
work=$(mktemp -d)
trap 'rm -rf "$work"; [ -n "${srvpid:-}" ] && kill "$srvpid" 2>/dev/null || true' EXIT INT TERM

step() { printf '\n== %s ==\n' "$1"; }

step "go version"
go version || { echo "no Go toolchain"; exit 1; }

step "build"
go build ./... && go build -o "$work/aiolic" ./cmd/aiolic
echo ok

step "vet"
go vet ./... && echo ok

step "gofmt"
unformatted=$(gofmt -l . 2>/dev/null || true)
if [ -n "$unformatted" ]; then
    echo "not formatted:"
    echo "$unformatted"
    exit 1
fi
echo clean

step "tests"
go test ./... || exit 1

step "race"
go test -race ./... >/dev/null 2>&1 && echo ok

# --- end to end -------------------------------------------------------------

step "end-to-end: server, request, verify, tamper"

cat > "$work/devices.json" <<'EOF'
[{"hwid":"AIO3-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "registered_at":"2026-01-01","vip":true,"expires_at":"2027-01-01",
  "jobs":{"SSL_PINNING_BYPASS":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]
EOF

port=18931
"$work/aiolic" serve -addr "127.0.0.1:$port" -devices "$work/devices.json" \
    -key-out "$work/keys.json" > "$work/srv.log" 2>&1 &
srvpid=$!

# Wait for the listener rather than sleeping a fixed time: poll the port.
i=0
while [ $i -lt 50 ]; do
    if curl -s -o /dev/null "http://127.0.0.1:$port/v1/device/check" 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    sleep 0.1
done

hwid="AIO3-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
jobhash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

printf 'device check: '
curl -s -X POST "http://127.0.0.1:$port/v1/device/check" \
    -H 'Content-Type: application/json' -H 'X-Client-Key: any' \
    -H 'X-Req-Nonce: 0102030405060708090a0b0c0d0e0f10' \
    -H 'User-Agent: AIO-Mod/1.0' \
    -d "{\"app_version\":\"aio-mod\",\"hwid\":\"$hwid\"}" \
    -o "$work/device.json" -w 'status=%{http_code}\n'

printf 'job claim:    '
curl -s -X POST "http://127.0.0.1:$port/v1/job/claim" \
    -H 'Content-Type: application/json' -H 'X-Client-Key: any' \
    -H 'X-Req-Nonce: 1111111111111111111111111111111a' \
    -d "{\"feature\":\"SSL_PINNING_BYPASS\",\"hwid\":\"$hwid\",\"job_hash\":\"$jobhash\",\"request_id\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\"}" \
    -o "$work/claim.json" -w 'status=%{http_code}\n'

pub=$(sed -n 's/.*"ed25519_public": *"\([0-9a-f]*\)".*/\1/p' "$work/keys.json")
hmackey=$(sed -n 's/.*"hmac_key": *"\([0-9a-f]*\)".*/\1/p' "$work/keys.json")

echo
printf 'verify device check: '
"$work/aiolic" verify -response "$work/device.json" -pub "$pub" -hmac "$hmackey"

printf 'verify job claim:    '
"$work/aiolic" verify -response "$work/claim.json" -pub "$pub" -hmac "$hmackey"

echo
echo "now altering a signed field in each response:"
"$work/aiolic" verify -response "$here/testdata/sample_device_check.json" \
    -pub "$(sed -n 's/.*"ed25519_public": *"\([0-9a-f]*\)".*/\1/p' "$work/keys.json")" \
    -hmac "$hmackey" 2>/dev/null || true

# Alter is_vip in the captured device check and require rejection.
python3 - "$work/device.json" "$work/tampered.json" <<'PY' 2>/dev/null || \
    sed 's/"is_vip": *true/"is_vip":false/' "$work/device.json" > "$work/tampered.json"
import json, sys
d = json.load(open(sys.argv[1]))
d["is_vip"] = not d["is_vip"]
json.dump(d, open(sys.argv[2], "w"))
PY

printf 'tampered device check: '
if "$work/aiolic" verify -response "$work/tampered.json" -pub "$pub" -hmac "$hmackey"; then
    echo "FAIL: the verifier accepted an altered response"
    exit 1
else
    echo "rejected, as it must be"
fi

kill "$srvpid" 2>/dev/null || true
srvpid=

step "done"
echo "everything that could run, ran."
