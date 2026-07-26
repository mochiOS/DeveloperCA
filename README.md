# mochiOS DeveloperCA

DeveloperCAはDeveloper、Developer Member、審査、追加作成申請、Developer
Certificate、trust store、失効情報を管理する独立サービスです。Rustと
`workers-rs`で実装し、Cloudflare WorkersとD1上で動作します。

認証主体とAccount状態はAccountsへ問い合わせます。GitHub OAuth tokenや
AccountsのSession DBを直接扱いません。また、App、Release、MPKG、Package
upload、R2などのObject Storage機能は含みません。

## ローカル実行

```sh
rustup target add wasm32-unknown-unknown
cargo install worker-build
npx wrangler d1 migrations apply mochios-developer-ca --local
npx wrangler dev
```

`.dev.vars`へ次のsecretを設定してください。

```text
SERVICE_TOKEN=<Accountsと共有するランダム値>
ADMIN_TOKEN=<管理API専用のランダム値>
INTERMEDIATE_PRIVATE_KEY=<base64形式の32 byte Ed25519 seed>
```

開発用Intermediate seedは`openssl rand -base64 32`で生成できます。本番の
Offline Root秘密鍵をこのWorkerへ配置してはいけません。

検証コマンド:

```sh
cargo test --lib
cargo clippy --target wasm32-unknown-unknown -- -D warnings
```

