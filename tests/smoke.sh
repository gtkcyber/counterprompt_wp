#!/usr/bin/env bash
# Black-box smoke test: acts as an attacker against a running site.
set -euo pipefail
BASE="${BASE:-http://localhost:8888}"
TRAP="/db-backup/"
fail() { echo "FAIL: $1"; exit 1; }
maze=$(mktemp); trap 'rm -f "$maze"' EXIT

# Requires pretty permalinks (wp rewrite structure '/%postname%/' --hard).
# 1. Static layer present on homepage, invisible to humans.
home=$(curl -s "$BASE/")
grep -q 'display:none' <<<"$home" || fail "no hidden honeypot link"
grep -q '<!--' <<<"$home" || fail "no notice comment"

# 2. robots.txt disallows trap paths.
robots=$(curl -s "$BASE/robots.txt")
grep -q "Disallow: $TRAP" <<<"$robots" || fail "robots missing trap"

# 3. Unflagged users endpoint returns data.
before=$(curl -s "$BASE/wp-json/wp/v2/users")
grep -q '\[' <<<"$before" || fail "users endpoint not returning array"

# 4. Trap hit: 200 + no-store + maze.
hdrs=$(curl -s -D - -o "$maze" "$BASE$TRAP")
head -1 <<<"$hdrs" | grep -q ' 200' || fail "trap not 200"
grep -qi 'cache-control:.*no-store' <<<"$hdrs" || fail "trap missing no-store"
grep -q '<li>' "$maze" || fail "trap not a maze"

# 5. Now flagged (same IP): users endpoint suppressed most of the time (p=0.7, expect ~35/50).
empty=0
for _ in $(seq 1 50); do
  r=$(curl -s "$BASE/wp-json/wp/v2/users")
  [ "$r" = "[]" ] && empty=$((empty+1))
done
[ "$empty" -ge 20 ] || fail "expected majority suppressed, got $empty/50"

echo "SMOKE OK ($empty/50 suppressed after flag)"
