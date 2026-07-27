# 失効snapshot

`GET /v1/revocations`は、信頼済みIntermediateが署名した累積snapshotを返します。
署名domainは`mochios-revocation-snapshot-v1\0`です。公開情報には固定reason codeだけを
含め、自由入力の内部reasonはD1監査用に留めます。

Certificate失効では次を同じD1 batchで更新します。

1. Certificateを`revoked`へ変更
2. 一意なrevocation行を追加
3. 旧current snapshotを解除
4. versionを増やした署名済み累積snapshotを追加
5. 監査ログを追加

snapshot生成前にD1の全失効行を読み直すため、過去の失効を省略できません。versionと
generated_atは単調増加し、同じversionの上書きはDB制約で拒否します。途中障害やmigration
後は管理APIの`revocation-snapshots/rebuild`を再実行し、D1の全失効から修復できます。

currentのcacheは60秒です。version指定snapshotはimmutableですが、クライアントは保持済み
最大versionより小さいsnapshotへ戻してはいけません。
