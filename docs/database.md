# D1データベース

既存のDeveloper、member、申請、証明書、失効、監査ログに加えて、次を保存します。

- `issuers`: Root署名snapshotから登録した複数Intermediate
- `trust_snapshots`: 変更しないRoot署名付きJSONとETag
- `revocation_snapshots`: 変更しないIntermediate署名付き累積JSONとETag
- `developer_package_scopes`: Developer単位のPackage ID許可
- `developer_capability_grants`: Developer単位のCapability許可
- `global_issuable_capabilities`: サービス全体で発行可能なCapability
- `authentication_replay_cache`: 期限付き、最大10,000件の使用済み`jti`

署名snapshotはtriggerで上書きと削除を禁止します。Issuerの同一key IDに対する公開鍵差し
替えも禁止します。証明書失効、失効レコード、次の累積snapshot、監査ログは同じD1 batch
へ入ります。証明書発行batch内でもpending状態、Developer状態、member role、全Policyを
再確認します。

Migrationは既存行を削除しません。初回trust snapshot未登録時は発行とsnapshot署名を
拒否します。既存失効は初回の管理者rebuildで署名付き累積snapshotへ取り込みます。
