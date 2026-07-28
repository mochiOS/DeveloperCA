# Developer Certificate形式

証明書は`mochios-certificate` crateが定義するMCER v1 binaryです。署名メッセージは次のdomain separatorを用います。

```text
mochios-certificate-v1\0 || canonical_certificate_bytes
```

証明書にはserial number、Root key ID、Developer ID、subject Ed25519公開鍵、有効期間、Package ID scope、許可Capability、Root署名が含まれます。Issuer key IDは証明書へ署名したRoot公開鍵から導出します。

DeveloperCAの内部UUIDはMCERのDeveloper IDに使いません。Consoleが表示する小文字の`certificate_developer_id`を`msign certificate issue --developer-id`へ指定します。

JSONは表示・API用の派生表現です。検証の正本には必ずraw MCER bytesを使用します。詳細なwire layoutはmochiOSの`docs/certificates.md`を正本とします。
