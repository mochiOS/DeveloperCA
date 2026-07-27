# アーキテクチャ

```text
Offline Root
  └─署名─> Issuer Trust Snapshot ─登録─> DeveloperCA / D1
                  ├─ active Intermediate
                  ├─ retired Intermediate
                  ├─ future Intermediate
                  └─ revoked Intermediate

Online Intermediate ─署名─> Developer Certificate
Trusted Intermediate ─署名─> 累積Revocation Snapshot

Console ─短期署名token─> DeveloperCA ─Account再確認─> Accounts
```

Offline Root秘密鍵はローカル専用CLIだけが使用します。WorkerはRoot公開鍵と、現在の
Online Intermediate秘密鍵だけを保持します。発行と失効snapshot生成では、Worker鍵の
公開鍵が現在のRoot署名付きsnapshotおよびD1 Issuer Registryと一致することを毎回確認
します。一致しない場合はfail closedです。

一般利用者のAccounts Bearer token introspection経路は維持します。Console代理操作は
`sub`にAccount IDを固定した60秒のdelegation tokenを使用します。管理操作も同じ署名
基盤のadmin tokenを使用し、actorは`sub`だけから決定します。

ConsoleのMPKG選択UIは端末内で`manifest.toml`を読み、`package.id`と全
`binary.requires`を申請候補へ自動反映します。これは入力支援であり信頼境界では
ありません。発行時はD1 Policyとactive memberをDeveloperCAが再検証します。
