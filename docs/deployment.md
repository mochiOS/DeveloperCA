# デプロイ

必要なSecretは次の3つです。

```text
SERVICE_TOKEN
CONSOLE_TOKEN_PUBLIC_KEY
MOCHIOS_ROOT_PUBLIC_KEYS_HEX
```

```powershell
npx wrangler secret put SERVICE_TOKEN
npx wrangler secret put CONSOLE_TOKEN_PUBLIC_KEY
npx wrangler secret put MOCHIOS_ROOT_PUBLIC_KEYS_HEX
npx wrangler d1 migrations apply mochios-developer-ca --remote
npx wrangler deploy
```

Root秘密鍵をSecretへ登録してはいけません。デプロイ後は`/health`、`/v1/trust-store`、登録済み証明書の`/status`を確認します。
