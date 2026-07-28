# mochiOS Developer CA

一般開発者へDeveloper Certificate（MCER v1）を発行し、Developer、Member、証明書、Issuer trust、失効状態を管理するRust／`workers-rs`製Cloudflare Workerです。状態はD1へ保存します。

通常発行はOnline Intermediateを使用します。Offline Root秘密鍵はCloudへ置かず、Root署名済みTrust Snapshotだけを登録します。

```text
Offline Root
  └─ Root署名済みTrust Snapshot
       └─ Online Intermediate
            └─ developer.cert（MCER v1）
```

開発者はConsoleで`application.pub`とunsigned `.mpkg`を選択します。MPKGはブラウザ内だけで解析され、APIへ届くのは公開鍵、完全一致Package ID、Capability集合だけです。Developerがactiveかつverifiedで、呼出Accountがactiveなowner／admin／developer Memberなら、人によるCertificate審査なしで即時発行します。viewerは一覧と再取得だけ可能です。

## API

```text
POST /v1/developers/:developer_id/certificates/issue
GET  /v1/developers/:developer_id/certificates
GET  /v1/certificates/:certificate_id
GET  /v1/certificates/:certificate_id/status
GET  /v1/trust-store
GET  /v1/trust-store/:snapshot_version
GET  /v1/revocations
GET  /v1/revocations/:snapshot_version
POST /v1/admin/trust-snapshots
POST /v1/admin/certificates/:certificate_id/revoke
```

発行入力:

```json
{
  "subject_public_key": "<Base64または64桁hexのEd25519公開鍵>",
  "package_id": "org.mochios.example",
  "capabilities": ["fs.read.all", "window.create"]
}
```

`X-Idempotency-Key`が必須です。成功応答の`certificate`がBase64のraw MCER bytesです。秘密鍵やMPKGを受理するfieldはありません。

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

Secret、Trust Snapshot登録、本番反映は[docs/deployment.md](docs/deployment.md)を参照してください。証明書発行の詳細は[docs/certificate-format.md](docs/certificate-format.md)、全体フローは[docs/architecture.md](docs/architecture.md)にあります。
