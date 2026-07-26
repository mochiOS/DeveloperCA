# データベース

D1にはdevelopers、developer_members、developer_creation_requests、
certificate_requests、certificates、revocations、audit_logsを保存します。
永続IDはすべてUUIDv7です。

serial numberとCertificate requestの関連は一意です。Certificate行には必ず
Developer IDを保存します。すべての動的SQL値はprepared statementへbindし、
Developer＋owner作成、承認枠消費、発行、失効はD1 batchで原子的に更新します。

Package path、bucket、release metadata、upload状態は保存しません。

