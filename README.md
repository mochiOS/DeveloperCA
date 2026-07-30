# mochiOS Developer CA

Developer、Member、Developer Certificate（MCER v1）、Issuer trust、失効状態の正本となるRust／`workers-rs`製Cloudflare Workerです。

一般発行はKome CLI専用です。Accountsが発行した短寿命Bearer tokenの署名、issuer、`developer-ca` audience、`kome-cli` client、scope、期限、session IDを検証し、Accounts introspectionでAccountと端末sessionが現在もactiveか確認します。さらに発行直前にDeveloperとactive membership、owner／admin／developer roleをD1から再確認します。

```text
GET  /v1/cli/developers
POST /v1/developers/:developer_id/certificates/issue
GET  /v1/developers/:developer_id/certificates
PATCH /v1/developers/:developer_id/certificates/:certificate_id
GET  /v1/certificates/:certificate_id
GET  /v1/certificates/:certificate_id/status
```

`PATCH`では`{"display_name":"Release signing"}`のように、署名内容へ影響しない管理用の証明書名を1〜80文字で設定できます。

Developer IDは32桁小文字UUIDv7本体です。Package IDは`org.mochios.*`に限定せず、2 segment以上の小文字reverse-domain形式を共有`mochios-certificate` validatorで検証します。一般APIが発行するscopeは完全一致1件だけです。

発行APIが受け取るのはDeveloper公開鍵、Package ID、Capability集合だけです。Developer秘密鍵、MPKG、payload、ローカルpath、refresh tokenは受け取りません。成功時の`certificate`はBase64 MCER wire bytesです。

```powershell
npx wrangler d1 migrations apply mochios-developer-ca --local
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo check --target wasm32-unknown-unknown
npx wrangler dev
```
