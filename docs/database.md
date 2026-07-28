# データベース

- `developers` / `developer_members`: Developerと権限
- `developer_creation_requests`: 追加Developerの申請
- `certificate_requests`: 登録時metadataと監査互換情報
- `certificates`: raw MCER v1のBase64、serial、Root key ID、subject key ID、有効期間、状態
- `revocations`: 失効serial、reason、実行者、時刻
- `audit_logs`: 追記専用監査ログ
- `authentication_replay_cache`: 管理tokenの再利用防止

過去のIssuer／trust snapshot用テーブルは`0004_root_direct_trust.sql`で削除します。MPKG本体や秘密鍵はD1へ保存しません。
