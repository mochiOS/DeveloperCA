# Developer Certificate発行

wire正本は共有`mochios-certificate` crateのMCER v1です。独自JSON Certificateを正本にしません。

- Developer ID: 32桁小文字UUIDv7本体
- Subject public key: DeveloperのEd25519公開鍵
- Subject Key ID: 公開鍵32 bytesのSHA-256
- Package scope: 有効なPackage IDへの完全一致1件
- Allowed Capability: manifest内の全`binary.requires`を正規化した集合
- Key usage: package signing
- Issuer: current Root署名Trust Snapshotのactive Online Intermediate
- 有効期限: Issuer期限と1年上限の短い方

入力には未知fieldを許可せず、秘密鍵、MPKG、payload、prefix scopeを受理しません。重複・不正Capability、512件超、16 KiB超のbodyを拒否します。管理者による発行承認はなく、管理者のCertificate操作は失効だけです。
