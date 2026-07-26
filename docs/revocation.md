# 失効

管理者による失効では、Certificate状態変更、UUIDv7 revocation記録、監査ログを
同じD1 batchで更新します。`certificate_id`の一意制約により失効記録は重複しません。

`GET /v1/revocations`はversion付きsnapshotを返します。
`GET /v1/certificates/{certificate_id}/status`は署名、有効期限、DBレコードとの
一致、Certificate状態、現在のDeveloper状態をまとめて確認します。

snapshot自体の署名と差分配布は未実装です。

