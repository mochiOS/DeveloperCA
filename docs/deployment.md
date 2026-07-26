# デプロイ

1. Accountsを先にデプロイし、本番URLを確認します。
2. D1 IDを設定してmigrationを適用します。
3. `SERVICE_TOKEN`、`CONSOLE_SERVICE_TOKEN`、`ADMIN_TOKEN`、
   `INTERMEDIATE_PRIVATE_KEY`をWorker secretへ登録します。
4. `ACCOUNTS_BASE_URL`、`ISSUER_KEY_ID`、Certificate TTLを設定します。
5. テストとWasm buildを確認して`wrangler deploy`を実行します。

Online Intermediateを更新するときはtrust storeへ新旧鍵を重複掲載する移行期間が
必要です。Offline Root秘密鍵やObject Storage bindingを追加してはいけません。

`CONSOLE_SERVICE_TOKEN`はAccounts、DeveloperCA、Consoleだけで共有し、通常の
`SERVICE_TOKEN`や`ADMIN_TOKEN`とは異なる256 bit以上の値を使用してください。
