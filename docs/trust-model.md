# Trustモデルとローテーション

Issuer Trust SnapshotはOffline Rootが
`mochios-issuer-trust-snapshot-v1\0 || canonical_snapshot_bytes`へ署名します。Issuerは
`future`、`active`、`retired`、`revoked`のいずれかです。activeは最大1件です。

- `future`: 将来用。発行不可
- `active`: 新規Certificate発行可
- `retired`: 新規発行不可。既存Certificate検証可
- `revoked`: 発行・検証とも不可

ローテーションは、future鍵を含むsnapshot、active切替snapshot、旧鍵をretiredにした
snapshotの順にRoot署名して登録します。旧鍵をretiredにしても、その有効期間内に発行
されたCertificateは無効になりません。同じkey IDへ別公開鍵を割り当てること、既存Issuer
を新snapshotから省略すること、statusを逆行させることは禁止します。

Worker内のOnline秘密鍵とactive issuerが一致しない期間は、意図的に新規発行を停止します。
鍵変更より前にRoot署名snapshotを準備してください。
