# 用語集

Smart Shield のドキュメントに出てくる用語の簡単な解説です。

## IP / IP アドレス
インターネット上の「住所」。`203.0.113.7` のような数字の組。サーバはこの単位で通信相手を識別します。
Smart Shield のブロックも IP 単位で行います。

## CIDR
複数の IP をまとめて表す書き方。`192.168.0.0/16` のように書くと「192.168 で始まる 65,536 個の IP すべて」を意味します。
ホワイトリストで「社内ネット全部」のように一括指定する用途で使います。

## ログ
サーバソフトが「いつ・誰が・何をしたか」を逐一書き残しているテキストファイル。
Smart Shield はこのファイルを読み続けて判定材料にします。

## tail (ティル)
ファイルの末尾を見続ける Unix の昔からの仕組み。新しい行が追記された瞬間に読み取れます。
Smart Shield の監視はこれと同等の動きをします。

## ログローテーション
ログファイルが肥大化しないよう、一定サイズ・期間ごとに別名で保存して新しい空ファイルに切り替える運用。
Smart Shield はこれを検知して、新しいファイルから読み直します。

## jail (ジェイル)
「監獄」の意味。Smart Shield では「あるログに対する判定ルールの組」を 1 つの jail と呼びます。
SSH 用、Nginx 用、メールサーバ用、と複数の jail を並べられます。

## ban / unban (バン / アンバン)
ban = ブロック (締め出す)、unban = 解除。通常 ban には期限があり、過ぎれば自動 unban されます。
**永久 ban** は手動で `unban` するまで解除されません。

## recidive (再犯)
過去 N 日以内に M 回 ban された相手を、次回の ban で **永久 ban に自動昇格** させる仕組み。
fail2ban にも同名の機能があります。`global.recidive.enabled` で ON/OFF。

## 永久 ban
有効期限を持たない ban (内部的には `expires_at = 0`)。
時間経過で外れず、手動 unban か `deactivate_ban` でしか解除されません。

## ホワイトリスト
「絶対にブロックしない IP の一覧」。自社オフィス、社内ネット、監視サービスなど、誤検知させたくない相手をここに入れておきます。

## ファイアウォール
通信を通すか捨てるかを決める OS 標準の関所。
- Linux では `iptables` / `nftables` / `ufw` / `firewalld` などが代表
- Windows では「Windows Defender ファイアウォール」(`netsh advfirewall`)

Smart Shield は自分でパケット処理せず、このファイアウォールに「この IP を捨てて」と頼みます。

## デーモン / サービス
バックグラウンドで動き続けるプログラム。Linux では「デーモン」、Windows では「サービス」と呼びます。
Smart Shield はデーモンとして 24 時間動かして使います。

## systemd
近年の Linux 標準のサービス管理機構。「自動起動」「落ちたら再起動」「ログ集約」を担当します。
Smart Shield 用の設定ファイル (unit) を [packaging/systemd/](../packaging/systemd/) に同梱しています。

## NSSM
Windows でプログラムを「サービス」として簡単に登録できる外部ツール。
Smart Shield の Windows 版インストールスクリプトはこれを使います。

## dry_run (ドライラン)
お試しモード。「本来ならブロックする」という判定だけして、実際の OS コマンドは打たない動作。
最初の運用や設定変更後の確認に必須です。

## SQLite
1 ファイルで完結する軽量データベース。Smart Shield はブロック中の IP・過去の試行・処理位置をすべてここに記録します。
`sqlite3 var/shield.sqlite3` で開いて SQL で集計できます。

## SOC
Security Operations Center。企業のセキュリティ監視チーム。Smart Shield の AI には「SOC のアナリストになったつもりで読んで」と指示しています。

## ブルートフォース
パスワードを片っ端から試して当てようとする攻撃。ルールエンジンが最も得意な検出対象です。

## credential stuffing
他のサイトで漏洩したパスワード一覧を、別サイトに使い回して試す攻撃。各 IP からは少回数なので AI 解析が活躍します。

## False positive / 誤検知
本当は無害な相手を「攻撃」と誤って判定してしまうこと。Smart Shield では `min_confidence` / `dry_run` / `ban_seconds` の組み合わせで影響を抑えます。

## API キー
AI プロバイダを呼び出すために必要な認証文字列。**秘密情報** なので公開リポジトリにコミットしないでください。
`.env` や systemd の `EnvironmentFile`、Windows サービスの環境変数経由で渡します。
- Anthropic Claude → `ANTHROPIC_API_KEY` ([Anthropic Console](https://console.anthropic.com/) で発行)
- Google Gemini → `GEMINI_API_KEY` (または `GOOGLE_API_KEY`) ([Google AI Studio](https://aistudio.google.com/apikey) で発行)

## プロンプトキャッシュ
AI に毎回同じ指示文 (システムプロンプト) を送るとき、2 回目以降を高速・低コストで処理してもらえる仕組み。
Anthropic Claude では `cache_control: ephemeral` を自動付与しています。Gemini にも別途 Context Caching API がありますが、Smart Shield のシステムプロンプトは短いので現在は未使用。

## Gemini
Google の大規模言語モデル群。`gemini-2.5-flash` は安価・高速で、構造化出力のタスクなら Claude Sonnet の 1/10 程度のコストで運用可能。
Smart Shield では `ai.provider: gemini` で選択。
