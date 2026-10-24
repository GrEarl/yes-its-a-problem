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

python3 lab_dns.py --role provider --bind 127.0.0.1 --port 15351 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --provider-ip 127.0.0.1 \
  --ttl 0 --log "$LOG" >/tmp/lab-provider.out 2>&1 &
PIDS+=($!)

python3 lab_dns.py --role true --bind 127.0.0.1 --port 15352 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --ttl 0 --log "$LOG" >/tmp/lab-true.out 2>&1 &
PIDS+=($!)

python3 lab_dns.py --role fake --bind 127.0.0.1 --port 15353 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --ttl 0 --log "$LOG" >/tmp/lab-fake.out 2>&1 &
PIDS+=($!)

sleep 1
for pid in "${PIDS[@]}"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "INCONCLUSIVE: a DNS fixture failed to start; see /tmp/lab-{provider,true,fake}.out" >&2
    exit 1
  fi
done

echo "=== dig +norecurse to the provider (referral with malicious ADDITIONAL)"
dig +norecurse +noall +comments +authority +additional @127.0.0.1 -p 15351 \
  "www.$CHILD.$ZONE" A
echo
echo "=== configured endpoint comparison (not a recursive resolver test)"
python3 simulate.py --name "www.$CHILD.$ZONE" --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP"
echo
echo "=== query log"
cat "$LOG"

echo "=== scenario 2: external child-NS contract (--child-ns, deployment topology)"
CHILD_NS="ns-child.yes-its-a-problem.iamwonderingif.com"

python3 lab_dns.py --role provider --bind 127.0.0.1 --port 15354 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" --child-ns "$CHILD_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --provider-ip 127.0.0.1 \
  --ttl 0 --log "$LOG" >/tmp/lab-xprovider.out 2>&1 &
PIDS+=($!)

python3 lab_dns.py --role true --bind 127.0.0.1 --port 15355 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" --child-ns "$CHILD_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --ttl 0 --log "$LOG" >/tmp/lab-xtrue.out 2>&1 &
PIDS+=($!)

python3 lab_dns.py --role fake --bind 127.0.0.1 --port 15356 \
  --zone "$ZONE" --child "$CHILD" --provider-ns "$PROVIDER_NS" --child-ns "$CHILD_NS" \
  --true-ip "$TRUE_IP" --fake-ip "$FAKE_IP" --ttl 0 --log "$LOG" >/tmp/lab-xfake.out 2>&1 &
PIDS+=($!)

sleep 1
for pid in "${PIDS[@]:3}"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "INCONCLUSIVE: an external-contract fixture failed to start; see /tmp/lab-x{provider,true,fake}.out" >&2
    exit 1
  fi
done

echo "=== referral for www.$CHILD.$ZONE (external NS + unrelated ADDITIONAL A -> fake IP)"
dig +norecurse +noall +comments +authority +additional @127.0.0.1 -p 15354 \
  "www.$CHILD.$ZONE" A
echo
echo "=== the provider holds no data for the external NS name (out-of-zone REFUSED)"
dig +norecurse +noall +comments @127.0.0.1 -p 15354 "$CHILD_NS" A
echo
echo "=== true authority answers with the normal address; NS uses the external name"
dig +norecurse +noall +answer +authority @127.0.0.1 -p 15355 "www.$CHILD.$ZONE" A
dig +norecurse +noall +answer @127.0.0.1 -p 15355 "$CHILD.$ZONE" NS
echo
echo "=== fake authority answers with the alternate address"
dig +norecurse +noall +answer @127.0.0.1 -p 15356 "www.$CHILD.$ZONE" A
echo
echo "=== query log (scenario 2 appended)"
cat "$LOG"
