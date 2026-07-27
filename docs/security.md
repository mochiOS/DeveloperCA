# セキュリティ

- 管理・代理tokenはEd25519署名付き、最大4 KiB、最大TTL 120秒です。
- `iss`、`aud`、`role`、`act`、`iat`、`exp`、`jti`を検証し、未知fieldを拒否します。
- actorは署名済み`sub`だけから取得し、AccountがactiveかAccountsへ再確認します。
- 重要操作は`jti`を一度だけ受理し、監査ログにも記録します。
- Offline Root秘密鍵をWorker、D1、CI、ログへ置きません。
- Online鍵はRoot署名snapshotとIssuer Registryの両方に一致するときだけ使用します。
- scopeとCapabilityは共有Certificate形式の厳格な文字列・件数・重複検証を通します。
- 発行直前とD1 batch内の両方で、Developer状態とactive member roleを再確認します。
- snapshotとCertificateには厳格な件数・byte数・文字列長上限があります。
- SQL値はprepared statementへbindし、snapshotと監査ログは追記専用です。

ConsoleはMPKG本体を送信せず、端末内で抽出したmanifest値だけを送ります。Developer
Certificateは「管理者がCapabilityを承認した」という意味ではなく、確認済みDeveloperの
公開鍵と署名可能範囲を暗号学的に結び付けるものです。実行時Capability認可とApp Store審査は
Certificate発行とは別の信頼境界です。
