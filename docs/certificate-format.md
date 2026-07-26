# 証明書形式

Version 1のDeveloper Certificateは次のcanonical JSONを署名します。

```text
format_version, serial_number, issuer_key_id, developer_id,
subject_key_id, subject_public_key, not_before, not_after, key_usage,
package_id_scopes, allowed_capabilities, signature_algorithm, signature
```

署名アルゴリズムはEd25519のみです。Developer秘密鍵はDeveloper側で生成し、
DeveloperCAへ送信しません。CertificateにはDeveloper IDを記録し、Account IDや
GitHub IDは含めません。

未知のfield、未対応version／algorithm、不正な公開鍵・署名・有効期間・key
usage・Package scopeを拒否します。`authorize`は完全一致または末尾`.*`の
Package scopeと、要求Capabilityがすべて許可済みであることをfail closedで確認します。

