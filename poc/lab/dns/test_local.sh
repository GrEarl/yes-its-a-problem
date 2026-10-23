#!/usr/bin/env bash
# Local, loopback-only exercise of the DNS lab.  No public traffic, no privileged ports.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../../.. && pwd)"
export PYTHONPATH="$ROOT/poc/vendor:${PYTHONPATH:-}"

ZONE="lab.yes-its-a-problem.iamwonderingif.com"
CHILD="v"
PROVIDER_NS="ns1.yes-its-a-problem.iamwonderingif.com"
TRUE_IP="192.0.2.10"
FAKE_IP="198.51.100.66"
LOG="$(mktemp -t lab-dns-log.XXXXXX)"
rm -f "$LOG"

cleanup() {
  kill "${PIDS[@]:-}" 2>/dev/null || true
}
trap cleanup EXIT
PIDS=()

python3 lab_dns.py --role provider --bind 127.0.0.1 --port 5351 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --provider-ip 127.0.0.1 \
  --ttl 0 --log "$LOG" >/tmp/lab-provider.out 2>&1 &
PIDS+=($!)

python3 lab_dns.py --role true --bind 127.0.0.1 --port 5352 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --ttl 0 --log "$LOG" >/tmp/lab-true.out 2>&1 &
PIDS+=($!)

python3 lab_dns.py --role fake --bind 127.0.0.1 --port 5353 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --ttl 0 --log "$LOG" >/tmp/lab-fake.out 2>&1 &
PIDS+=($!)

sleep 1
if ! kill -0 "${PIDS[0]}" 2>/dev/null; then
  echo "provider failed to start"; cat /tmp/lab-provider.out; exit 1
fi

echo "=== dig +norecurse to the provider (referral with malicious ADDITIONAL)"
dig +norecurse +noall +comments +authority +additional @127.0.0.1 -p 5351 \
  "www.$CHILD.$ZONE" A
echo
echo "=== full safe/vulnerable simulation"
python3 simulate.py --name "www.$CHILD.$ZONE"
echo
echo "=== query log"
cat "$LOG"
