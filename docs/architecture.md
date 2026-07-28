# アーキテクチャ

```text
application.key ── 開発者端末だけで保持
application.pub ─┐
unsigned .mpkg ──┴─> Consoleのブラウザ内解析
                         └─ 公開鍵・Package ID・Capabilityのみ
                                      ↓ Service Binding + 60秒delegation token
Accounts <── active確認 ── Developer CA Worker
                              ├─ Developer／Member確認
Offline Root公開鍵 ───────────┤─ Trust Snapshot検証
Online Intermediate秘密鍵 ───┤─ 公開鍵一致確認
                              └─ MCER v1発行／D1保存
                                      ↓
                                 developer.cert
```

発行直前にAccount、Developer、Member、入力、現在のRoot署名Trust Snapshot、active Issuer、有効期間、Worker秘密鍵から導出した公開鍵を再確認します。不一致はすべてfail closedです。

D1 batchはCertificate request、Certificate record、発行Account、発行経路、idempotency完了、監査ログを一貫して保存します。serialはD1の単調増加sequenceから予約し、途中失敗でも再利用しません。同一内容の同時実行と5分以内の再送は同じCertificateへ集約し、その後は意図的な再発行を許可します。

既存Root直署名Certificateは`issuance_source=legacy_root`として保持し、Offline Root公開鍵で検証を継続します。新規の一般発行だけを`online_intermediate`へ限定します。
