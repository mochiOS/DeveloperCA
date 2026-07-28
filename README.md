# mochiOS DeveloperCA

DeveloperCAはDeveloperアカウントと、オフラインで発行されたDeveloper Certificateの登録・失効状態を管理するCloudflare Workerです。Rustと`workers-rs`で実装し、状態はD1へ保存します。

証明書の正本は`mochios-certificate` crateが定義するMCER v1です。証明書はmochiOSリポジトリの`tools/devkit/crates/msign`でRoot秘密鍵を使ってオフライン発行し、ConsoleからMCERファイルを登録します。WorkerはRoot公開鍵で署名・有効期限・Package ID scope・Capabilityを検証します。管理者は証明書を発行・承認せず、失効だけを行います。

D1の内部Developer UUIDとは別に、MCERへ格納する`certificate_developer_id`（`org.mochios.developer.<uuid>`）を各Developerへ割り当てます。`msign certificate issue --developer-id`にはConsoleに表示されるこの値を指定します。

Root秘密鍵をWorker、D1、CI、`.dev.vars`へ置いてはいけません。

## ローカル確認

```powershell
rustup target add wasm32-unknown-unknown
cargo install worker-build
npx wrangler d1 migrations apply mochios-developer-ca --local
cargo test --all-targets
cargo check --target wasm32-unknown-unknown
npx wrangler dev
```

`.dev.vars`には次を設定します。

```text
SERVICE_TOKEN=<Accounts内部API用token>
CONSOLE_TOKEN_PUBLIC_KEY=<Console短期token署名鍵のBase64 Ed25519公開鍵>
MOCHIOS_ROOT_PUBLIC_KEYS_HEX=<Root Ed25519公開鍵の64文字hex。複数はカンマ区切り>
```

## 証明書API

```text
POST /v1/developers/:developer_id/certificates/register
GET  /v1/developers/:developer_id/certificates
GET  /v1/certificates/:certificate_id
GET  /v1/certificates/:certificate_id/status
GET  /v1/trust-store
GET  /v1/revocations
POST /v1/admin/certificates/:certificate_id/revoke
```

登録リクエストは`{"certificate":"<MCER v1のBase64>"}`です。
