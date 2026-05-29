# smart-shield

ログを常時監視して攻撃元 IP を自動でブロックする常駐デーモンです。正規表現によるルールベース検出と、AI (Claude または Gemini) を使った定期的な AI ログ解析を組み合わせています。

> 仕組み解説は [docs/](docs/) を参照してください。

- **ルールベース jail**: 正規表現で失敗イベントを検出し、`max_retries / findtime` を超えた IP を `ban_seconds` 間ファイアウォールでブロック。
- **AI アナライザ**: 指定間隔で直近ログを Claude / Gemini に投げ、シグネチャに乗らない不審 IP (低速スキャン、credential stuffing、shell 探索など) を JSON で抽出して ban。コスト最優先なら Gemini 2.5 Flash で月数百円から運用可能。
- **プラットフォーム対応**: Windows は `netsh advfirewall`、Linux は `iptables`。`dry_run: true` の間は実コマンドは打たず DB に記録だけ残します。
- **永続化**: SQLite に試行記録・ban・ログ位置を保存。再起動しても最後のオフセットから tail を再開。

## ファイル構成

```
shield/
  __main__.py        # CLI エントリポイント (run / status / ban / unban)
  config.py          # YAML 読込
  monitor.py         # ローテーション対応 async tail
  filters.py         # 正規表現フィルタ
  jail.py            # スライディング窓カウンタ + ban 判定
  banner.py          # 実 OS ファイアウォール操作 (dry_run 対応)
  ai_analyzer.py     # Anthropic API を使った定期解析
  store.py           # SQLite 永続化
config/
  shield.yaml        # メイン設定
  filters/*.yaml     # フィルタ定義 (sshd / nginx-auth / apache-auth など)
examples/            # サンプルログ
tests/               # pytest 用テスト
```

## 動かし方

主な対象は Linux サーバ (Ubuntu / Debian / RHEL 系) です。Windows でもフォアグラウンド実行は可能。

### Ubuntu / Debian

```bash
# 必要パッケージ (Python と iptables)
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iptables

# プロジェクトを取得 (例: /opt 配下)
sudo git clone <repo-url> /opt/smart-shield
cd /opt/smart-shield

# venv を作って依存導入
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# AI 機能を使う場合
export ANTHROPIC_API_KEY="sk-ant-..."

# まずは dry_run=true のまま前景起動して挙動を確認
python -m shield -c config/shield.yaml run
```

### RHEL / Rocky / AlmaLinux

```bash
sudo dnf install -y python3 python3-pip iptables-services
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."
python -m shield -c config/shield.yaml run
```

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:ANTHROPIC_API_KEY = "sk-ant-..."
python -m shield -c config/shield.yaml run
```

### 状況確認 (どの OS でも共通)

別ターミナルで:

```bash
python -m shield -c config/shield.yaml status               # 今アクティブな ban
python -m shield -c config/shield.yaml ban   1.2.3.4 --seconds 3600 --reason "manual"
python -m shield -c config/shield.yaml unban 1.2.3.4
```

`dry_run: true` の間は実 firewall コマンドは発行されず、SQLite (`var/shield.sqlite3`) に
記録だけ残るので、`status` の出力と DB をしばらく眺めて誤検知が無いことを確認してください。

## 設定の要点

`config/shield.yaml` の主なキー:

| キー | 意味 |
|---|---|
| `global.dry_run` | true の間は実 firewall コマンドを打たない (動作確認用) |
| `global.whitelist` | CIDR で除外。AI 判定にも適用 |
| `global.recidive.{enabled,lookback_seconds,max_bans}` | 再犯者の自動永久 ban (有効時、過去 `lookback_seconds` 内に `max_bans` 回 ban された IP は次回永久 ban) |
| `jails.<name>.paths` | 監視するログファイル (存在しなければスキップ) |
| `jails.<name>.max_retries / findtime_seconds` | スライディング窓と閾値 |
| `jails.<name>.ban_seconds` | 通常 ban の継続時間。**`0` を指定すると永久 ban** |
| `ai.enabled` | AI 解析の ON/OFF |
| `ai.provider` | `anthropic` または `gemini` (キー: `ANTHROPIC_API_KEY` / `GEMINI_API_KEY`) |
| `ai.model` | 省略時は provider 別のデフォルト (`claude-sonnet-4-6` / `gemini-2.5-flash`) |
| `ai.interval_seconds` | 解析周期 (秒) |
| `ai.lookback_seconds` | 1 回の解析で参照する直近時間幅 |
| `ai.min_confidence` | この信頼度未満の AI 提案は無視 (誤検知抑制) |
| `ai.ban_seconds` | AI 由来 ban の継続時間 (`0` で永久 ban) |

フィルタ定義は `config/filters/*.yaml`。各 pattern には必ず `(?P<ip>...)` 名前付きグループが必要です。

## AI 解析の動作

1. tail で集めたログを path 別の deque に滞留させる (TTL = lookback × 4)。
2. `interval_seconds` 間隔で直近 `lookback_seconds` 分のログを連結し、`max_log_chars` を超える場合は末尾を残してトリム。
3. プロンプトキャッシュ付きで Claude (`ai.model`) に投げ、JSON で `{blocks:[{ip,reason,confidence,evidence_lines}]}` を受け取る。
4. whitelist チェックと `min_confidence` を通過したものだけ `add_ban` + 実 block 実行。

## 同梱フィルタ

| フィルタ | 対象 | 主な検出内容 |
|---|---|---|
| `sshd` | OpenSSH の認証ログ | パスワード/公開鍵失敗、無効ユーザ、認証中の切断 |
| `nginx-auth` | Nginx access log | 401/403 連発、`/.env` `/wp-admin` `/.git/` 等の探索 |
| `apache-auth` | Apache access_log + error_log | 401/403、scanner パス、`mod_auth_basic` の認証失敗、`mod_security` ブロック |

`apache-auth` は access log と error log の **どちらにも対応** しています。jail の `paths` に両方を列挙すれば、フィルタが行ごとに適切なパターンを当てて IP を抽出します。

Apache の典型的なログ位置:
- Debian/Ubuntu: `/var/log/apache2/{access,error}.log`
- RHEL/Rocky: `/var/log/httpd/{access,error}_log`
- Windows: `C:/Apache24/logs/{access,error}.log`

## ban / unban の流れ

- jail: `record_attempt → count_recent_attempts >= max_retries → add_ban + banner.block`
- 期限切れ: `unban_loop` が 30 秒ごとに `list_expired` を回し、`banner.unblock + deactivate_ban`
- **永久 ban (`expires_at = 0`)** は `list_expired` から除外され、`unban` コマンドか `deactivate_ban` を呼ぶまで解除されない
- 再犯エスカレーション: `add_ban` 直前に `events` を集計し、`global.recidive.max_bans` を超えていれば `ban_seconds = 0` に書き換え
- 起動時に SQLite の active な ban を OS ファイアウォールに再登録 (再起動で iptables ルールが消えても永久 ban が効き続ける)
- 全イベントは `events` テーブルに記録 (kind: `ban` / `ban-perm` / `ai-ban` / `ai-ban-perm` / `unban` / `reapply` …)

### 手動で永久 ban する

```bash
python -m shield ban 203.0.113.7 --permanent --reason "known bad actor"
python -m shield unban 203.0.113.7   # 解除は手動でのみ可能
```

## サービスとして常駐させる

フォアグラウンドの `python -m shield run` をそのまま放っておくとターミナルが閉じた瞬間に死ぬので、本番では OS のサービスマネージャに登録します。`packaging/` にテンプレートを同梱。

### Ubuntu / Debian (systemd)

```bash
# 1. 必要パッケージ
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iptables git

# 2. 配置と venv
sudo mkdir -p /opt/smart-shield /etc/smart-shield /var/lib/smart-shield /var/log/smart-shield
sudo git clone <repo-url> /opt/smart-shield
sudo python3 -m venv /opt/smart-shield/.venv
sudo /opt/smart-shield/.venv/bin/pip install -r /opt/smart-shield/requirements.txt

# 3. 設定ファイルを /etc/ 配下に分離 (state_db: /var/lib/smart-shield/shield.sqlite3 などに書き換える)
sudo cp /opt/smart-shield/config/shield.yaml      /etc/smart-shield/shield.yaml
sudo cp -r /opt/smart-shield/config/filters       /etc/smart-shield/filters
sudo cp /opt/smart-shield/packaging/systemd/env.example /etc/smart-shield/env
sudo chmod 600 /etc/smart-shield/env              # ANTHROPIC_API_KEY を書き込む
sudo $EDITOR /etc/smart-shield/shield.yaml        # paths を /var/log/auth.log などに調整

# 4. systemd unit を登録
sudo cp /opt/smart-shield/packaging/systemd/smart-shield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now smart-shield

# 5. 確認
sudo systemctl status smart-shield
journalctl -u smart-shield -f
```

#### Ubuntu で ufw を使っている場合

Ubuntu の標準ファイアウォール `ufw` は内部で iptables を使っているので、Smart Shield が `iptables -I INPUT ... DROP` を打つと **ufw のルールより前に挿入** され、即座に効きます。ただし `ufw reload` / `ufw disable` で smart-shield 由来のルールも巻き添えで消えるので、以下を推奨:

```bash
# 状態を確認しつつ smart-shield を再起動すれば、SQLite から再 ban される
sudo ufw status numbered
sudo systemctl restart smart-shield
```

恒久的な統合をしたい場合は `shield/banner.py` の `iptables` 呼び出しを `ufw insert 1 deny from <ip>` に差し替えると、`ufw status` から見える形で管理できます。

### RHEL / Rocky / AlmaLinux (systemd)

`apt` を `dnf` に置き換えるだけで上と同じ手順です:

```bash
sudo dnf install -y python3 python3-pip iptables-services git
# 以降は Ubuntu と同じ (git clone → venv → cp → systemctl)
```

`firewalld` がデフォルトで動いていますが、`iptables -I INPUT` は firewalld ルールより上位に入るので動作します。
ただし `firewall-cmd --reload` で消えるので、ufw の場合と同様に `shield/banner.py` を `firewall-cmd --add-rich-rule="rule family=ipv4 source address=<ip> drop"` に差し替えるのが綺麗です。

### unit ファイルのカスタマイズ

[packaging/systemd/smart-shield.service](packaging/systemd/smart-shield.service) は

- `Restart=on-failure` / `RestartSec=5` で落ちたら自動再起動
- `KillSignal=SIGTERM` で graceful shutdown
- `ProtectSystem=full` / `PrivateTmp=true` で書込先を絞る (`ReadWritePaths=` は実環境に合わせて編集)
- 標準出力は `journald` に流す

を設定済みです。専用ユーザで動かしたい場合は `User=` / `Group=` を変えて、`CAP_NET_ADMIN` を `AmbientCapabilities=` で付与してください。

### Windows (NSSM, 推奨)

[NSSM](https://nssm.cc/) をインストールして `nssm.exe` を PATH に通したあと、管理者 PowerShell で:

```powershell
# venv を作って依存を入れる
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
deactivate

# サービス登録 (AppRoot / Python / Config を引数で上書き可)
$env:ANTHROPIC_API_KEY = "sk-ant-..."
.\packaging\windows\install-service-nssm.ps1
```

これで `SmartShield` という Windows サービスが作られ、自動起動・落ちたら 5 秒で再起動・stdout/stderr を `var\log\shield.{out,err}.log` にローテートして書き出します。

```powershell
Get-Service SmartShield                       # 状態
Stop-Service SmartShield                      # 停止
Get-Content var\log\shield.out.log -Wait      # ログを tail
nssm remove SmartShield confirm               # アンインストール
```

### Windows (NSSM が使えない場合)

`schtasks` ベースの簡易版も用意してあります ([packaging/windows/install-task-scheduler.ps1](packaging/windows/install-task-scheduler.ps1))。起動時に SYSTEM 権限で起動し、落ちたら 1 分後に再起動します。

```powershell
.\packaging\windows\install-task-scheduler.ps1
```

ただし Task Scheduler は NSSM ほど厳格な制御ができないため (graceful stop なし、log rotation なし)、本番では NSSM 経由を推奨します。

### 多重起動の検出

サービス起動時に `var/shield.pid` を書き出します。OS のサービスマネージャが二重起動を防ぐのが本筋ですが、手動で `python -m shield run` を叩いてしまったときに気付けるよう、既存 PID が見つかると WARNING ログを出します。

## テスト

```powershell
pip install pytest pytest-asyncio
pytest -q
```

## 本番利用時の注意

- 必ず最初は `dry_run: true` で動かして、jail が誤検知しないか・AI が無害な IP を flag しないかを `status` と SQLite (`var/shield.sqlite3`) で確認してください。
- Windows で iptables 系コマンドが必要な場合や、Linux で nftables を使いたい場合は `shield/banner.py` を差し替えるだけで対応できます。
- 自分のクライアント IP を必ず `global.whitelist` に入れてください。AI が誤判定しても締め出されません。
