# 運用

一般開発者は`msign key generate`で`application.key`と`application.pub`を作り、Consoleで公開鍵とunsigned MPKGを選択して`developer.cert`を取得します。その後、開発者端末で次を実行します。

```powershell
msign package sign application.mpkg --certificate developer.cert --key application.key --output application-signed.mpkg
msign package verify application-signed.mpkg --root-public-key <trusted-key> --unix-time <unix>
```

`kome sign`はlegacy `.pkg`用です。MPKGのDeveloper Certificate付き署名には`msign package sign`を使用します。

運営者はOffline Root、Trust Snapshot、Issuerローテーションを管理します。一般発行へRoot秘密鍵を使いません。Issuerローテーションは新IssuerをfutureとしてSnapshotへ追加し、新しいSnapshotでactiveを切り替え、旧Issuerをretired、侵害時はrevokedへ単調に遷移させます。

Certificate失効はConsole管理画面からreason codeと説明を付けて行います。失効serialは再利用しません。AppStoreは登録、Reviewer報告、公開承認の各段階でDeveloper CA statusを確認します。
