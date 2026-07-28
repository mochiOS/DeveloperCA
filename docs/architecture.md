# アーキテクチャ

```text
オフラインRoot秘密鍵
  └─ msign ─> Root直署名MCER v1 ─> Console ─> DeveloperCA / D1

mochiOS・AppStore reviewer
  └─ 組み込みRoot公開鍵でMCER v1を検証
```

DeveloperCAは秘密鍵を保持せず、証明書を発行しません。登録時にMCER v1をdecodeし、設定済みRoot公開鍵による署名、有効期限、Developer ID、Package ID scope、Capabilityを検証します。D1にはMCERのBase64と検索・監査用metadataを保存します。

Consoleはログイン中のactive memberから証明書を受け取り、短期delegation tokenでDeveloperCAへ登録します。管理者向け操作はDeveloper確認、追加Developer申請の審査、証明書失効だけです。

Intermediate CA、Issuer Registry、trust snapshot、オンライン署名鍵は使用しません。
