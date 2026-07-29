# デプロイ

## Worker Secret

```text
SERVICE_TOKEN                 Accounts内部APIと同じランダムtoken
CONSOLE_TOKEN_PUBLIC_KEY      Console delegation署名鍵に対応するBase64 Ed25519公開鍵
INTERMEDIATE_PRIVATE_KEY      Online IntermediateのBase64 Ed25519 32-byte seed
OFFLINE_ROOT_PUBLIC_KEY       Offline RootのBase64 Ed25519 32-byte公開鍵
OFFLINE_ROOT_KEY_ID           Offline Root公開鍵bytesのSHA-256 lowercase hex
```

`OFFLINE_ROOT_PRIVATE_KEY`のようなSecretは作成しません。Root秘密鍵をWorker、D1、Console、AppStore、CI、`.dev.vars`へ置いてはいけません。

```powershell
npx wrangler secret put SERVICE_TOKEN
npx wrangler secret put CONSOLE_TOKEN_PUBLIC_KEY
npx wrangler secret put INTERMEDIATE_PRIVATE_KEY
npx wrangler secret put OFFLINE_ROOT_PUBLIC_KEY
npx wrangler secret put OFFLINE_ROOT_KEY_ID
npx wrangler d1 migrations apply mochios-developer-ca --remote
npx wrangler deploy
```

## Trust Snapshotのオフライン作成

`tools/developer-ca-root`は隔離した運用端末で実行します。RootとIssuerの秘密鍵出力は上書きしません。

```powershell
cargo run --release --manifest-path tools/developer-ca-root/Cargo.toml -- root create --private-key root.seed --public-record root-public.json
cargo run --release --manifest-path tools/developer-ca-root/Cargo.toml -- issuer create --private-key intermediate.seed --record intermediate.json --not-before <unix> --not-after <unix> --status active --usage developer-certificate-signing --usage revocation-signing
cargo run --release --manifest-path tools/developer-ca-root/Cargo.toml -- trust-snapshot issue --root-key root.seed --issuer intermediate.json --version 1 --generated-at <unix> --expires-at <unix> --output trust-snapshot.json
cargo run --release --manifest-path tools/developer-ca-root/Cargo.toml -- trust-snapshot verify --snapshot trust-snapshot.json --root-public-record root-public.json --at <unix>
```

`intermediate.seed`だけを`INTERMEDIATE_PRIVATE_KEY`へ登録し、`root.seed`はオフラインへ戻します。Trust Snapshotは短期署名済みDeveloper CA admin tokenで`POST /v1/admin/trust-snapshots`へJSON本体のまま登録します。管理トークンは`CONSOLE_TOKEN_PUBLIC_KEY`に対応する専用のConsole delegation署名鍵で発行し、Offline Root鍵では署名しません。

```powershell
cargo run --release --manifest-path tools/developer-ca-root/Cargo.toml -- admin-token issue --signing-key console-token.seed --subject <active-account-uuid> --issued-at <unix> --expires-at <unix-within-120-seconds> --output admin-token.txt
```

tokenのactorはactive Accountでなければならず、寿命は最大120秒、jtiは一度だけ使用できます。登録後は`admin-token.txt`を削除します。`root.seed`が署名するのはTrust Snapshotそのものであり、オンラインAPI認証には使用しません。

## 反映確認

1. `/health`が200
2. `/v1/trust-store`のRoot署名、期限、active Issuerが正しい
3. `/v1/admin/issuers`のactive公開鍵がWorker秘密鍵から導出した公開鍵と同じ
4. テストDeveloperで発行し、MCER issuer key ID、scope、Capabilityを確認
5. 失効後に`/v1/certificates/:id/status`が`valid=false`を返す

本番で過去migrationによりIssuer stateが欠けている場合、発行を開始する前に既存のRoot署名済みSnapshotを復元するか、より新しい正当なSnapshotを再登録します。空のRegistryのまま発行を試みてもWorkerは503でfail closedします。
