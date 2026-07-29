# セキュリティ

- Developer秘密鍵とMPKGを受け取らない
- Offline Root秘密鍵をCloud、D1、CI、通常の開発端末へ置かない
- WorkerのOnline Intermediate秘密鍵をSecret以外へ保存・出力しない
- 一般発行はAccounts署名のKome CLI tokenだけを使用し、issuer、audience、client、scope、期限、session状態を検証する
- Web CookieやDeveloper IDだけでは一般発行を許可しない
- active Account、Developer、Member roleを発行時に再検証する
- Root署名Trust Snapshot、Issuer Registry、Worker秘密鍵の公開鍵を毎回照合する
- active Issuerが0件、複数、不一致、期限外、revokedならfail closedにする
- MCERは共有crateだけで生成・検証する
- serialはD1で一意かつ再利用不能にする
- body、Capability数、有効期限、Account／Developer／公開鍵ごとの発行数を制限する
- raw MCERとDB metadataの不一致、失効、期限切れをstatusで拒否する
- 管理tokenは短命、固定audience、active actor、jti一回限りにする

公開statusはCertificate秘密情報を含みません。返す公開鍵、key ID、serial、Developer IDはAppStoreがMPKG内MCERと一致確認するための公開identityです。
