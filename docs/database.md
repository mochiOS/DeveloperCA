# データベース

- `developers`／`developer_members`: Developerとactive role
- `developer_creation_requests`: 追加Developer作成申請
- `issuers`: Root署名Trust Snapshotと一致するIssuer Registry
- `trust_snapshots`: Root署名済み、追記型のTrust Snapshot
- `certificate_serial_sequence`: 再利用しない単調増加serial
- `certificate_issue_idempotency`: 5分間の同時・重複発行抑制
- `certificate_issuance_attempts`: Account／Developer／公開鍵単位の1時間制限
- `certificate_requests`: 公開鍵、scope、Capability、発行Account・経路
- `certificates`: raw MCER Base64、Issuer、serial、Subject Key ID、有効期間、発行種別
- `revocations`／`revocation_snapshots`: 失効記録と署名済みsnapshot
- `audit_logs`: 追記専用監査ログ
- `authentication_replay_cache`: 短期管理tokenのjti再利用防止

MPKG本体、Developer秘密鍵、Offline Root秘密鍵は保存しません。migration `0006_online_certificate_issuance.sql`は既存Certificateとserialを維持し、既存行を`legacy_root`として段階移行します。
