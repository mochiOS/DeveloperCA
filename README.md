# mochiOS DeveloperCA

DeveloperCAは、Developerアカウント、署名証明書、Issuer Registry、署名付きtrust
snapshot、署名付き失効snapshot、発行Policyを管理するCloudflare Workerです。Rustと
`workers-rs`で実装し、状態はD1へ保存します。MPKG本体やアプリ本体は保存しません。

Developer Certificateのwire形式と検証規則は、`mochios-certificate`共有crateを正本に
します。DeveloperCA内の`certificate.rs`はAPIとの変換だけを行う薄いadapterです。

## ローカル確認

```powershell
rustup target add wasm32-unknown-unknown
cargo install worker-build
npx wrangler d1 migrations apply mochios-developer-ca --local
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo check --target wasm32-unknown-unknown
npx wrangler dev
```

`.dev.vars`には次を設定します。

```text
SERVICE_TOKEN=<Accounts内部API用token>
INTERMEDIATE_PRIVATE_KEY=<Online Intermediateのbase64 Ed25519 32-byte seed>
CONSOLE_TOKEN_PUBLIC_KEY=<Console token署名鍵のbase64 Ed25519公開鍵>
OFFLINE_ROOT_PUBLIC_KEY=<Offline Rootのbase64 Ed25519公開鍵>
OFFLINE_ROOT_KEY_ID=<Offline Root公開鍵のSHA-256 hex>
```

Offline Root秘密鍵をWorker、D1、CI、`.dev.vars`へ置いてはいけません。初期化と鍵の
ローテーションは[運用手順](docs/operations.md)を参照してください。

## 公開API

```text
GET /v1/trust-store
GET /v1/trust-store/:snapshot_version
GET /v1/revocations
GET /v1/revocations/:snapshot_version
GET /v1/certificates/:certificate_id/status
```

current snapshotは短時間cacheとETag、version指定snapshotはimmutable cacheを返します。
