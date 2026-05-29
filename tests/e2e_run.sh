#!/usr/bin/env bash
# Full pytest + e2e regression for smart-shield. Run inside a Docker container
# that has iptables installed and NET_ADMIN cap. Mounts /work at the repo root.
set -e

apt-get update -qq && apt-get install -y -qq iptables 2>&1 | tail -1
pip install --quiet pyyaml watchdog pytest pytest-asyncio 2>&1 | tail -1

echo "=== [0] pytest 全件 ==="
python -m pytest -q 2>&1

reset_env() {
  pkill -f "shield" 2>/dev/null || true
  iptables -F INPUT 2>/dev/null || true
  rm -rf /tmp/state /tmp/cfg /tmp/logs /tmp/shield*.log
  mkdir -p /tmp/state /tmp/cfg/filters /tmp/logs
  cp /work/config/filters/*.yaml /tmp/cfg/filters/
}

write_cfg() {
  local dry_run=$1 ban_sec=$2 ai_enabled=$3 recidive_enabled=$4 max_bans=$5
  cat > /tmp/cfg/shield.yaml <<EOF
global:
  state_db: /tmp/state/shield.sqlite3
  log_level: INFO
  dry_run: $dry_run
  default_ban_seconds: 60
  whitelist:
    - 127.0.0.1
  recidive:
    enabled: $recidive_enabled
    lookback_seconds: 3600
    max_bans: $max_bans
jails:
  sshd:
    enabled: true
    filter: sshd
    paths:
      - /tmp/logs/sshd.log
    max_retries: 3
    findtime_seconds: 60
    ban_seconds: $ban_sec
ai:
  enabled: $ai_enabled
  provider: anthropic
  model: claude-sonnet-4-6
  interval_seconds: 300
  lookback_seconds: 900
  max_log_chars: 60000
  min_confidence: 0.75
  ban_seconds: 3600
  sources:
    - /tmp/logs/sshd.log
EOF
}

PASS=0
FAIL=0
check() {
  if [ "$1" = "ok" ]; then
    PASS=$((PASS+1))
    echo "  [PASS] $2"
  else
    FAIL=$((FAIL+1))
    echo "  [FAIL] $2"
  fi
}

count_attempts() {
  python -c "import sqlite3; c=sqlite3.connect('/tmp/state/shield.sqlite3'); print(list(c.execute(\"SELECT COUNT(*) FROM attempts WHERE ip=?\", (\"$1\",)))[0][0])"
}
count_event_kind() {
  python -c "import sqlite3; c=sqlite3.connect('/tmp/state/shield.sqlite3'); print(list(c.execute(\"SELECT COUNT(*) FROM events WHERE kind=?\", (\"$1\",)))[0][0])"
}

###############################################################################
echo
echo "=== [PHASE 1] dry_run 基本動作 ==="
reset_env
write_cfg true 60 false false 3
touch /tmp/logs/sshd.log
python -m shield -c /tmp/cfg/shield.yaml run > /tmp/shield.log 2>&1 &
PID=$!
sleep 2
for i in 1 2 3; do
  echo "Jan 01 12:00:0$i sshd[1]: Failed password for root from 203.0.113.7 port 51001 ssh2" >> /tmp/logs/sshd.log
done
sleep 3

STATUS=$(python -m shield -c /tmp/cfg/shield.yaml status)
echo "$STATUS" | grep -q "203.0.113.7" && check ok "ban 検出 (dry_run)" || check ng "ban 検出 (dry_run)"
grep -q "dry-run.*would block 203.0.113.7" /tmp/shield.log && check ok "dry_run で would block ログ" || check ng "dry_run で would block ログ"

kill -TERM $PID; wait $PID 2>/dev/null || true
grep -q "shutting down" /tmp/shield.log && check ok "graceful shutdown" || check ng "graceful shutdown"
test ! -f /tmp/state/shield.sqlite3-wal && check ok "WAL ファイル巻取り" || check ng "WAL ファイル巻取り"

###############################################################################
echo
echo "=== [PHASE 2] 実 iptables 統合 ==="
reset_env
write_cfg false 30 false false 3
touch /tmp/logs/sshd.log
python -m shield -c /tmp/cfg/shield.yaml run > /tmp/shield.log 2>&1 &
PID=$!
sleep 2
for i in 1 2 3; do
  echo "Jan 01 12:00:0$i sshd[1]: Failed password for root from 198.51.100.42 port 51001 ssh2" >> /tmp/logs/sshd.log
done
sleep 3
iptables -L INPUT -n | grep -q "198.51.100.42.*0.0.0.0/0" && check ok "iptables に DROP rule 追加" || check ng "iptables DROP"

for i in 4 5 6 7 8; do
  echo "Jan 01 12:00:0$i sshd[1]: Failed password for root from 198.51.100.42 port 51001 ssh2" >> /tmp/logs/sshd.log
done
sleep 3
COUNT=$(iptables -L INPUT -n | grep -c "198.51.100.42")
test "$COUNT" = "1" && check ok "rule 重複防止 (count=$COUNT)" || check ng "rule 重複防止 (count=$COUNT)"

python -m shield -c /tmp/cfg/shield.yaml unban 198.51.100.42 > /dev/null
iptables -L INPUT -n | grep -q "198.51.100.42" && check ng "手動 unban で rule 削除" || check ok "手動 unban で rule 削除"

kill -TERM $PID; wait $PID 2>/dev/null || true

###############################################################################
echo
echo "=== [PHASE 3] 永久 ban + throttle + 格下げ拒否 + rotation ==="
reset_env
write_cfg true 0 false false 3
touch /tmp/logs/sshd.log
python -m shield -c /tmp/cfg/shield.yaml run > /tmp/shield.log 2>&1 &
PID=$!
sleep 2

for i in 1 2 3; do
  echo "Jan 01 12:00:0$i sshd[1]: Failed password for root from 203.0.113.7 port 51001 ssh2" >> /tmp/logs/sshd.log
done
sleep 2

STATUS=$(python -m shield -c /tmp/cfg/shield.yaml status)
echo "$STATUS" | grep -q "permanent" && check ok "永久 ban (ban_seconds=0)" || check ng "永久 ban"

for i in 4 5 6 7 8 9; do
  echo "Jan 01 12:01:0$i sshd[1]: Failed password for root from 203.0.113.7 port 51001 ssh2" >> /tmp/logs/sshd.log
done
sleep 2

ATT=$(count_attempts "203.0.113.7")
test "$ATT" -ge "9" && check ok "永久 ban 中 record_attempt ($ATT 件)" || check ng "永久 ban 中 record_attempt ($ATT 件)"

PERMA_HIT=$(count_event_kind "perma-ban-hit")
test "$PERMA_HIT" = "1" && check ok "perma-ban-hit throttle (=1 件)" || check ng "perma-ban-hit throttle (=$PERMA_HIT 件)"

DOWNGRADE=$(python -m shield -c /tmp/cfg/shield.yaml ban 203.0.113.7 --seconds 60)
echo "$DOWNGRADE" | grep -q "already permanently banned" && check ok "永久 ban 格下げ拒否" || check ng "永久 ban 格下げ拒否"

mv /tmp/logs/sshd.log /tmp/logs/sshd.log.1
touch /tmp/logs/sshd.log
echo "Jan 01 12:02:01 sshd[1]: Failed password for root from 203.0.113.88 port 51001 ssh2" >> /tmp/logs/sshd.log
echo "Jan 01 12:02:02 sshd[1]: Failed password for root from 203.0.113.88 port 51001 ssh2" >> /tmp/logs/sshd.log
echo "Jan 01 12:02:03 sshd[1]: Failed password for root from 203.0.113.88 port 51001 ssh2" >> /tmp/logs/sshd.log
sleep 3
grep -q "rotation detected" /tmp/shield.log && check ok "ローテーション検出" || check ng "ローテーション検出"
python -m shield -c /tmp/cfg/shield.yaml status | grep -q "203.0.113.88" && check ok "新ファイル側で ban 動作" || check ng "新ファイル側で ban 動作"

kill -TERM $PID; wait $PID 2>/dev/null || true

###############################################################################
echo
echo "=== [PHASE 5] AI 無効化 + recidive + reapply + CLI 検証 ==="
reset_env
write_cfg false 5 true true 2
touch /tmp/logs/sshd.log
python -m shield -c /tmp/cfg/shield.yaml run > /tmp/shield.log 2>&1 &
PID=$!
sleep 3

grep -q "ai-loop completed normally; idling" /tmp/shield.log && check ok "AI 無効時 idle (バグ #9 修正)" || check ng "AI 無効時 idle"
kill -0 $PID 2>/dev/null && check ok "AI 無効でも daemon 継続" || check ng "AI 無効でも daemon 継続"

for i in 1 2 3; do
  echo "Jan 01 12:00:0$i sshd[1]: Failed password for root from 198.51.100.5 port 51001 ssh2" >> /tmp/logs/sshd.log
done
sleep 2
iptables -L INPUT -n | grep -q "198.51.100.5" && check ok "1 回目 ban" || check ng "1 回目 ban"

sleep 35
iptables -L INPUT -n | grep -q "198.51.100.5" && check ng "自動 unban" || check ok "自動 unban"

for i in 4 5 6; do
  echo "Jan 01 12:01:0$i sshd[1]: Failed password for root from 198.51.100.5 port 51001 ssh2" >> /tmp/logs/sshd.log
done
sleep 2
python -m shield -c /tmp/cfg/shield.yaml status | grep "198.51.100.5" | grep -q "permanent" && check ok "recidive で永久化" || check ng "recidive で永久化"

kill -TERM $PID; wait $PID 2>/dev/null || true
iptables -F INPUT
python -m shield -c /tmp/cfg/shield.yaml run > /tmp/shield2.log 2>&1 &
PID=$!
sleep 3
iptables -L INPUT -n | grep -q "198.51.100.5" && check ok "reapply で iptables 復元" || check ng "reapply で iptables 復元"

kill -TERM $PID; wait $PID 2>/dev/null || true
python -m shield -c /tmp/cfg/shield.yaml run > /tmp/shield3.log 2>&1 &
PID=$!
sleep 3
COUNT=$(iptables -L INPUT -n | grep -c "198.51.100.5")
test "$COUNT" = "1" && check ok "再起動 rule 累積防止 (count=$COUNT)" || check ng "再起動 rule 累積防止 (count=$COUNT)"
kill -TERM $PID; wait $PID 2>/dev/null || true

python -m shield -c /tmp/cfg/shield.yaml ban "not-an-ip" 2>&1 | grep -q "invalid ip" && check ok "CLI: not-an-ip 拒否" || check ng "CLI: not-an-ip 拒否"
python -m shield -c /tmp/cfg/shield.yaml ban "999.999.999.999" 2>&1 | grep -q "invalid ip" && check ok "CLI: 999.999.999.999 拒否" || check ng "CLI: 999.999.999.999 拒否"
python -m shield -c /tmp/cfg/shield.yaml ban "1.2.3.4 garbage" 2>&1 | grep -q "invalid ip" && check ok "CLI: 空白混じり 拒否" || check ng "CLI: 空白混じり 拒否"

echo
echo "=================================="
echo "PASS: $PASS / FAIL: $FAIL"
echo "=================================="
test "$FAIL" = "0" && echo "ALL GREEN" || { echo "FAILURES DETECTED"; exit 1; }
