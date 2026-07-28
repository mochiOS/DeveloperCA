# Developer Certificate発行

証明書のwire正本は共有`mochios-certificate` crateのMCER v1です。Developer CAは独自JSON証明書を生成せず、共有crateでencode・署名したraw bytesを保存して返します。

通常のConsole発行では次を固定します。

- Developer ID: D1内部UUIDとは別の`certificate_developer_id`
- Subject public key: `application.pub`のEd25519公開鍵
- Subject Key ID: 公開鍵32 bytesのSHA-256
- Package scope: `package.id`への完全一致1件
- Allowed Capability: 全`[[binary]].requires`のソート済み和集合
- Key usage: package signing
- Issuer: current Root署名Trust Snapshotのactive Online Intermediate
- 有効期限: Issuer期限と1年上限の短い方

API応答の`certificate`はBase64 MCER、`certificate_details`は表示用の派生情報です。`developer.cert`へ保存するのは`certificate`をdecodeしたbytesです。

`application.key`は送信しません。32-byte秘密鍵seedを64-byteの公開鍵として送る入力や、未知field、不正Package ID、不正・重複Capability、512件超のCapability、16 KiB超のbodyは拒否します。32-byte seedと32-byte公開鍵はbyte列だけでは区別できないため、Consoleは`.key`ファイル名を拒否し、Developer CAはEd25519公開鍵としてdecodeできる入力だけを受理します。

管理者による発行承認はありません。管理者のCertificate操作は失効だけです。
