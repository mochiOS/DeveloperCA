# D1データベース

既存のDeveloper、member、申請、証明書、失効、監査ログに加えて、次を保存します。

- `issuers`: Root署名snapshotから登録した複数Intermediate
- `trust_snapshots`: 変更しないRoot署名付きJSONとETag
- `revocation_snapshots`: 変更しないIntermediate署名付き累積JSONとETag
- `authentication_replay_cache`: 期限付き、最大10,000件の使用済み`jti`

署名snapshotはtriggerで上書きと削除を禁止します。Issuerの同一key IDに対する公開鍵差し
替えも禁止します。証明書失効、失効レコード、次の累積snapshot、監査ログは同じD1 batch
へ入ります。証明書は申請行を`issued`として作成し、証明書行と監査ログを同じD1 batchへ
保存します。batch内でもDeveloper状態とmember roleを再確認します。

`0003_automatic_certificate_issuance.sql`は旧pending Certificate申請を再提出対象として
閉じ、旧発行Policy tableを削除します。既存の発行済み証明書、失効、監査ログは保持します。
初回trust snapshot未登録時は発行とsnapshot署名を拒否します。
