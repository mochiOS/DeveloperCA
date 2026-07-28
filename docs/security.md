# セキュリティ

- Root秘密鍵はCloudflare、D1、CI、Consoleへ置きません。
- Workerが保持するCA関連情報はRoot公開鍵だけです。
- 登録時はMCER v1の署名、有効期間、Developer ID、scope、Capabilityをfail closedで検証します。
- 変更APIはactive AccountとDeveloper member roleを確認します。
- 管理APIは短期署名token、allowlist、jti再利用防止、監査ログを必須にします。
- 証明書失効はserial単位で記録し、mochiOS imageへ反映します。
- MPKGやアプリ本体は保存しません。
