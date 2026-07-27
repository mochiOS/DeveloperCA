# デプロイ

1. `cargo test --all-targets`、Wasm check、clippyを実行します。
2. `npx wrangler d1 migrations apply mochios-developer-ca --remote`を実行します。
3. 次のWorker secretを設定します。

```text
SERVICE_TOKEN
INTERMEDIATE_PRIVATE_KEY
CONSOLE_TOKEN_PUBLIC_KEY
OFFLINE_ROOT_PUBLIC_KEY
OFFLINE_ROOT_KEY_ID
```

4. Consoleへ`DEVELOPER_CA_TOKEN_SIGNING_KEY`を設定します。対応する公開鍵だけを
   DeveloperCAへ設定します。
5. DeveloperCAを先、Consoleを後にデプロイします。
6. Offline CLIで署名した初回trust snapshotを管理APIへ登録します。
7. `POST /v1/admin/revocation-snapshots/rebuild`で既存失効を含む初回snapshotを作ります。
8. `/v1/trust-store`と`/v1/revocations`の署名、ETag、versionをローカルCLIで確認します。

旧`ADMIN_TOKEN`、`CONSOLE_SERVICE_TOKEN`、`X-Admin-Account-ID`、`X-Account-ID`は使用しません。
Root秘密鍵はWorker secretにも設定しません。詳細は[運用手順](operations.md)を参照して
ください。
