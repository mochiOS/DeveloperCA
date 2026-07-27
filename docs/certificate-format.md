# Developer Certificate形式

証明書形式の正本はmochiOS workspaceの`mochios-certificate`共有crateです。
DeveloperCA、`msign`、`signature.service`は同じcrateを使用します。

Version 1は`MCER` magicを持つ決定的なbinary wire形式です。整数はlittle-endian、文字列と
配列は固定長prefix、field順序は固定、scopeとCapabilityは昇順かつ重複禁止、未知version
と非ゼロreserved fieldは拒否します。JSON再シリアライズ結果を署名仕様にしません。

既存MPKGとの互換性を維持するため、Version 1のdomain separator
`mochios-certificate-v1\0`は変更しません。別domainへ変更する場合はwire format version
を上げ、旧Version 1検証を残す必要があります。同じVersion 1のままdomainだけを変える
移行は禁止です。

CertificateにはDeveloper ID、Subject公開鍵、Package ID scope、許可Capabilityを含めます。
Developer秘密鍵、Account ID、GitHub IDは含めません。Subject Key IDはSubject公開鍵から、
Issuer Key IDはIntermediate公開鍵から計算します。
