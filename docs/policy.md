# Certificate自動発行

Consoleは`.mpkg`内の`manifest.toml`から次を自動入力します。

```text
[package].id          -> requested Package ID scope
[[binary]].requires[] -> requested Capabilityの和集合
```

DeveloperCAは次の全条件を満たす場合、管理者審査を挟まず同じHTTPリクエスト内で
Certificateを発行します。

```text
Developer       = activeかつverified
Requester       = active memberかつowner/admin/developer
Issuer          = Root署名trust snapshotとIssuer Registryの両方でactive
Package scope   = 共有Certificate形式で妥当
Capability      = 共有Certificate形式で妥当、重複なし
```

発行前の確認に加えて、申請行・証明書行・監査ログを保存するD1 batch内でもDeveloperと
memberを再検証します。管理APIにはCertificate issue/reject routeを公開せず、active
Certificateのrevokeだけを公開します。Certificateに含まれるCapabilityは管理者承認を
意味せず、OS実行時認可とApp Store審査は別途行います。
