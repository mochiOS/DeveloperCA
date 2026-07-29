# 運用

一般開発者の操作はdevkitへ集約します。

```powershell
kome login
kome keygen
kome sign
```

`kome sign`はローカルMPKGのmanifestからPackage IDと全`binary.requires`の和集合を読み、公開鍵とそのmetadataだけをDeveloperCAへ送ります。返されたMCERをMPKGへ組み込み、秘密鍵で`manifest.sig`を生成します。秘密鍵とMPKG本体はCloudへ送信しません。

運営者はDeveloper確認、Certificate失効、Offline Root、Issuerローテーションを管理します。Certificate発行の人手審査はありません。AppStoreは登録、Reviewer報告、公開承認の各段階でstatusを再確認します。

開発中の環境ではTrust Snapshotを未登録のままにできます。その場合、一般発行は503でfail closedします。
