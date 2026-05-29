# よくある質問

## Q. 正規のお客さんがブロックされたりしませんか？

意図的にしつこく失敗を繰り返さない限り、まずブロックされません。

- 通常のログインで 1〜2 回パスワードを打ち間違えるくらいでは閾値に届かない (デフォルトは「10 分以内に 5 回失敗」)
- それでも心配なら `dry_run: true` のまま運用し、`status` の出力を眺めて顔ぶれを確認できます
- 万一ブロックされても **時間経過で自動解除されます** (デフォルト 1 時間)

社内 IP やオフィスの固定 IP は `global.whitelist` に書いておけば 100% 除外されます。

## Q. ブロックされた人はどうなりますか？

そのサーバ宛のすべての通信が、ファイアウォールの段階で **無言で破棄** されます。
ブラウザにエラーが出るというより、「サーバが応答しない」状態に見えます。

ブロックが解けると、また普通にアクセスできるようになります。
ブロックされたこと自体は相手に通知されません。

## Q. AI を使わないと意味がないですか？

いいえ。ルールエンジンだけでも一般的なブルートフォースや既知スキャナはほとんど止められます。
AI 解析は **ルールでは取りこぼす攻撃** (低速・分散・新種) を拾うための上乗せ機能です。

`ai.enabled: false` にすればルールだけで動作します。

## Q. 何のログを見るんですか？

設定ファイル (`config/shield.yaml` の `paths`) で指定したファイルだけです。代表例:

- `/var/log/auth.log` (Linux の認証ログ、SSH や sudo の試行)
- `/var/log/nginx/access.log` (Nginx のアクセスログ)
- `/var/log/apache2/{access,error}.log` (Apache、Debian/Ubuntu)
- `/var/log/httpd/{access,error}_log` (Apache、RHEL/Rocky)
- Windows なら OpenSSH や `C:/Apache24/logs/` 配下

アプリケーションのデータベース、ファイルの中身、メールなどには一切触れません。

## Q. Apache (httpd) でも使えますか？

はい。`apache-auth` フィルタを同梱しており、**access_log と error_log の両方** から攻撃を拾います:

- access_log: 401/403 連発、`/.env` `/wp-login.php` `/phpmyadmin` `/server-status` `/manager/html` `/HNAP1` 等の典型的なスキャナ URL
- error_log: `mod_auth_basic` の認証失敗、`client denied by server configuration`、`mod_security` ブロック

jail 設定で両方のログを `paths` に並べておけば、フィルタが行ごとに適切なパターンを当てます。
[config/shield.yaml](../config/shield.yaml) の `jails.apache-auth` がそのまま使える例です。

## Q. ブロック中の相手を一覧で見たい

```bash
python -m shield -c config/shield.yaml status
```

「いつ」「どこからの」「どの jail で」「あと何秒残ってる」「理由」が並びます。
詳細を SQL で見たければ:

```bash
sqlite3 var/shield.sqlite3 "SELECT * FROM bans WHERE active=1"
sqlite3 var/shield.sqlite3 "SELECT * FROM events ORDER BY id DESC LIMIT 50"
```

## Q. 緊急で誰かを手動でブロック / 解除したい

```bash
# 1 時間ブロック
python -m shield ban 203.0.113.7 --seconds 3600 --reason "manual via support ticket"

# 即時解除
python -m shield unban 203.0.113.7
```

## Q. Smart Shield が落ちたらブロックも外れますか？

外れません。ブロックは OS のファイアウォールに登録されているため、Smart Shield のプロセスが落ちても効いたままです。
ただし systemd / NSSM 経由で動かしておけば、落ちても自動で再起動するので心配いりません。

## Q. サーバが再起動したらどうなりますか？

- `iptables` のルールは **再起動で消えます** (Linux の標準動作)。
- ただし Smart Shield は SQLite に ban を保存しており、**起動時に有効な ban をすべて OS ファイアウォールに再登録** します。
  つまり OS 再起動後も、Smart Shield が立ち上がった瞬間にブロックが元通り効きます。
- 一時 ban も永久 ban も同じ仕組みで復元されます。

## Q. 永久にブロックしたい IP があります

3 通りあります。

1. **手動で永久 ban**
   ```bash
   python -m shield ban 203.0.113.7 --permanent --reason "known bad actor"
   ```
   解除するまで自動 unban されません。
2. **jail / ai 設定で `ban_seconds: 0`**
   `shield.yaml` の `jails.<name>.ban_seconds: 0` または `ai.ban_seconds: 0` にすると、その経路で ban されたものはすべて永久になります (慎重に)。
3. **再犯者の自動永久化 (recidive)**
   `global.recidive.enabled: true` にしておくと、過去 `lookback_seconds` (デフォルト 7 日) 以内に `max_bans` (デフォルト 3) 回 ban された IP は、次回 ban 時に **自動で永久 ban に昇格** します。「何度も ban を待ってやり直す相手」を最終的に締め出す仕組みです。

## Q. 永久 ban したい人を解除したい

```bash
python -m shield unban 203.0.113.7
```

永久 ban も同じコマンドで解除できます。永久 ban は時間経過では絶対に外れず、手動 unban か `deactivate_ban` を呼ぶことでのみ解除されます。

## Q. AI に送るログを最小限にしたい

`shield.yaml` の `ai.sources` に並べたパスだけが AI に送られます。
ジェイル監視 (`jails.*.paths`) と AI 監視 (`ai.sources`) は独立しているので、AI には認証ログだけ渡し、
個人情報を含むアプリログは AI に送らない、という構成が可能です。

## Q. AI の判断は信頼できますか？

100% ではありません。だからこそ次の多層防御を入れています:

1. AI 自身が出す `confidence` がしきい値未満なら無視
2. ホワイトリスト IP は AI が指名しても除外
3. ban 時間を短めに設定すれば誤検知でも自動解除
4. すべての判定理由と元になったログは SQLite に残り後から監査可能

最初は `dry_run: true` + 短めの `ai.ban_seconds` で運用し、ログを見ながら微調整するのが現場的な流れです。

## Q. クラウドに置いてあるサーバでも使えますか？

使えます。EC2 / Compute Engine / Azure VM など、Linux/Windows がそのまま動くインスタンスならどれでも OK。

ただしクラウドのセキュリティグループ (AWS でいう SG) は VPC 入口で効くもので、Smart Shield の `iptables` は **インスタンス内** で効きます。両方を併用するのが安全です。

## Q. WAF (Cloudflare 等) を入れている場合は？

WAF の背後に置く場合、サーバから見たクライアント IP が WAF のものになります。
そのままだと WAF の IP をブロックしかねないので、必ず次のどちらかを行ってください:

- WAF が `X-Forwarded-For` ヘッダで実 IP を伝えている → ウェブサーバ側で実 IP をログに出すよう設定する (Nginx なら `real_ip_module`)
- フロント WAF 側の IP は全部 `global.whitelist` に登録する

## Q. AI を Claude じゃなくて Gemini にできますか？

できます。`shield.yaml` で:

```yaml
ai:
  provider: gemini             # anthropic | gemini
  model: gemini-2.5-flash      # gemini-2.5-pro / gemini-2.5-flash-lite なども
```

API キーは `GEMINI_API_KEY` (または `GOOGLE_API_KEY`) 環境変数で渡します。
**Gemini 2.5 Flash は Claude Sonnet の 1/10 程度のコスト** で、構造化抽出 (JSON 出力) のタスクは十分こなせるので、コスト重視ならまず Gemini Flash がおすすめです。

| 推奨用途 | プロバイダ | モデル |
|---|---|---|
| コスト最優先 | Gemini | `gemini-2.5-flash-lite` |
| バランス | Gemini | `gemini-2.5-flash` |
| 精度重視 (英語ログ多め) | Anthropic | `claude-sonnet-4-6` |
| 最高精度 | Anthropic | `claude-opus-4-7` |

SDK は `pip install '.[gemini]'` のように使う方だけ入れれば OK です。

## Q. ライセンス / 料金は？

- Smart Shield 本体: OSS (リポジトリ参照)
- AI 機能を使う場合: 選んだプロバイダ (Anthropic か Google) の API 利用料が別途必要 (使った分だけ)

AI を切れば追加料金は発生しません。
