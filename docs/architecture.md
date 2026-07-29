# アーキテクチャ

```text
Kome CLI --短寿命token + 公開鍵/Package ID/Capability--> DeveloperCA
   |                                                        |
   | MPKG/秘密鍵はローカル                                  +-- Accounts CLI session introspection
   |                                                        +-- Developer/Member/role再確認
   |                                                        +-- Root署名Trust/active Issuer確認
   +<---------------- Base64 MCER wire ----------------------+
```

Developer IDはDeveloper tableの32桁UUIDv7本体をMCER、API path、AppStore metadataへそのまま使用します。Account IDは人間の認証主体であり、Developer IDを知っていることを認証や認可に使いません。

D1 batchはCertificate request、Certificate record、発行Account、発行経路、idempotency、監査ログを一貫して保存します。serialは単調増加sequenceから予約し、途中失敗でも再利用しません。
