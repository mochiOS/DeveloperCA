# Trustモデル

本番の信頼階層は次のとおりです。

```text
Offline Root CA
    -> Online Developer Intermediate CA
        -> Developer Certificate
```

Offline Root秘密鍵をWorker、D1、CI、ログへ配置してはいけません。実装済みsigner
が受け取る`INTERMEDIATE_PRIVATE_KEY`は、開発用直接issuerまたはOnline
IntermediateのEd25519 seedです。`/v1/trust-store`はissuer ID、algorithm、
公開鍵だけを公開します。

Root ceremony、Intermediate証明書作成、HSM統合は将来構想であり未実装です。

