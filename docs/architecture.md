# アーキテクチャ

## 実装済み構成

```text
利用者Bearer token -> DeveloperCA Worker -> Accounts introspection
                              |
                              +-> D1（Developer／Certificate）
                              +-> Online Intermediate signer secret
公開利用者 <--------------- trust store／証明書状態／失効情報
```

利用者操作ではAccountsをfail closedで確認した後、activeなmembershipとroleを
確認します。管理APIは通常Sessionと分離した`ADMIN_TOKEN`とactiveな管理
Account IDを要求します。複数レコードの変更にはD1 batchを使用します。

## 将来構想

HSMや独立signer serviceへの移行は未実装です。証明書形式を維持したまま
Online Intermediate秘密鍵の保管先を置換できる設計です。

