# セキュリティ

- 管理・代理tokenはEd25519署名付き、最大4 KiB、最大TTL 120秒です。
- `iss`、`aud`、`role`、`act`、`iat`、`exp`、`jti`を検証し、未知fieldを拒否します。
- actorは署名済み`sub`だけから取得し、AccountがactiveかAccountsへ再確認します。
- 重要操作は`jti`を一度だけ受理し、監査ログにも記録します。
- Offline Root秘密鍵をWorker、D1、CI、ログへ置きません。
- Online鍵はRoot署名snapshotとIssuer Registryの両方に一致するときだけ使用します。
- scopeとCapabilityは申請値、Developer grant、global policyを発行直前とD1 batch内で照合します。
- snapshotとCertificateには厳格な件数・byte数・文字列長上限があります。
- SQL値はprepared statementへbindし、snapshotと監査ログは追記専用です。

ConsoleのブラウザMPKG解析は入力補助です。ブラウザから送られたscopeやCapabilityを信頼
せず、DeveloperCAがPolicyを再検証します。`fs.read.all`、`process.spawn`、
`window.overlay`のような強いCapabilityをmanifestだけでglobal許可にしてはいけません。
