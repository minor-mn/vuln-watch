# Vuln Watch

監視対象製品のCVE判定と、ITセキュリティ・AIの話題を管理するアプリです。

## 取得元と更新

`config/information_sources.yml` の4項目を `true` / `false` にして取得元を選びます。既定はすべて有効です。

```yaml
cve: true
github_advisory: true
full_disclosure: true
slashdot: true
```

環境変数 `INFORMATION_SOURCES=cve,full_disclosure,slashdot` でも上書きできます。空文字を設定すると全取得元を停止します。設定変更後はアプリを再起動してください。一覧画面のチェックボックスは表示対象の絞り込みです。

本番ではPuma内のSolid Queueが60分ごとに `InformationSyncJob` を動かし、有効な取得元を個別ジョブで更新します。`scripts/start` は従来どおりSolid Queueも起動します。初回取得や手動更新は、DBマイグレーション後に `RAILS_ENV=production bin/rails information:refresh` で予約できます。CVEの更新では従来の評価・通知も動きます。

- CVE: 既存のCVE List差分取得と監視対象製品の照合・判定・通知を維持します。
- GitHub Advisory Database: 公式APIのレビュー済み・未撤回アドバイザリを公開日時順に取得し、必要な分だけページをたどります。`GITHUB_ADVISORY_TOKEN` は任意です。
- Full Disclosure: 公式RSSの報告と返信を保存します。`Re:` / `Re[n]:` の返信は独立した話題として要約・紹介しません。
- Slashdot: 公式AtomからITセキュリティ・AIに関する投稿を選び、一覧の最後の「話題」に載せます。緊急CVE扱いで通知しません。

一覧画面とAPIの条件未指定時は、各取得元について24時間以内の投稿が5件以上ならその全件、5件未満なら期間を問わず最新5件を表示・API対象にします。CVEは監視対象として保存済みのレコードから同じ条件で選びます。日付不明・未来日付・重複URLは除外します。取得したフィード内の有効な投稿とGitHubの取得ページ内の有効な投稿は、表示件数や期間にかかわらず保存・事前要約します。変更のない保存済み要約は再利用します。過去の保存行は削除せず、ローリングフィードの範囲から古くなって外れただけでも履歴を参照できます。今回取得した掲載期間内から消えた投稿は表示対象から外します。外部情報をCVE原本として登録したり、要約だけを根拠に緊急判定やメール送信をしたりしません。GitHub・Full Disclosureで既存の監視CVEと番号が対応する場合はその区分に、それ以外は「未判定」に表示します。

日本語の短い紹介は既存の `OPENAI_API_KEY` / `OPENAI_MODEL` で事前生成します。入力が変わらなければ要約を再利用します。要約未設定・失敗時は元の見出しと警告を返します。Slashdotは要約未作成の間、キーワードで関連投稿を選びます。記事本文はDBに保持し、会話用抜粋は600文字までにします。

Slashdotの公開コメントは評価順、Full Disclosureの返信は対象投稿の子孫だけをスレッド順に、最大12件・各1200文字で保管します。引用文・スクリプト・メール定型フッターを除き、取得失敗と一部取得を記録します。CVEとGitHubのコメントは対象外です。

## 最新情報API

`GET /api/briefing` はDBの現在のデータからJSONを返します。JSONファイルの作成、外部サイト取得、LLMの呼び出しは行いません。`/watch/` 配下なら公開URLは `/watch/api/briefing` です。

クエリパラメータは次の3つです。

| パラメータ | 指定内容 |
|---|---|
| `sources` | `cve,github_advisory,full_disclosure,slashdot` の任意の組み合わせ。省略時は有効な全取得元。空指定は0件 |
| `hours` | 何時間前までの公開情報を返すか。正の数（`0.5`などの小数も可） |
| `limit` | **取得元ごと**の最大件数。正の整数。新しい順に選ぶ |

```text
GET /api/briefing?sources=cve,full_disclosure,slashdot&hours=48&limit=10
```

この例は各取得元から過去48時間以内の話題を最大10件ずつ返します。`sources[]=cve&sources[]=slashdot` という配列指定も使えます。

- `hours`・`limit`を**両方省略**すると、従来の「24時間以内は全件、5件未満なら最新5件」の選別を維持します。
- どちらかを指定すると期間を厳守し、期間外の記事で件数を補充しません。`hours`だけなら件数上限なし、`limit`だけなら過去24時間です。条件指定時の件数上限は関連性のある話題に適用し、独立したFull Disclosure返信は件数に数えません。
- 未知の取得元、0・負数・不正な時間/件数は400を返します。無効化した取得元は指定しても対象外です。
- 保存済みの情報から選ぶため、収集開始前の未保存データをAPIへのアクセスで新たに取得することはありません。GitHubの取得は毎回24時間分と最新5件が揃うページまでで、そのページの有効な投稿をすべて蓄積します。RSSは取得フィードに含まれる範囲です。

応答は `version: 1`、`news`（`since`・`as_of`・`selection_policy`・`hours`・`limit`・全 `items`・短い冒頭文 `text`）、話題と同じ順の `threads`、`warnings`、取得元ごとの更新状態 `sources` です。冒頭文だけ最大4件と残り件数に絞り、全話題・コメントは応答に保持します。更新に失敗しても以前のDBデータを残し、更新遅延や取得失敗を警告します。`as_of` は応答の選択基準時刻、`sources.*.last_success_at` は各取得元の最終更新時刻です。

同一ホストのsi-human側では `VULN_WATCH_API_URL=http://127.0.0.1:3000/api/briefing` を設定します（Pumaのポートに合わせて変更）。`VULN_WATCH_HOURS=48` / `VULN_WATCH_LIMIT=10` でAPIの条件を指定でき、両方省略すると従来の選別です。si-humanは接続準備時に一度だけこのAPIを読み、コメントは質問された後にだけ会話へ渡します。

## 反映

追加マイグレーションで情報投稿と取得状態のテーブルを作ります。通常のデプロイ手順（`bin/rails db:prepare`、アセット生成、再起動）で反映してください。取得元のAPIキーはvuln-watch側に置きます。
