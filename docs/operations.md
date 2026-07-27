# Offline Root初期化と運用

`developer-ca-root`はローカル専用です。秘密鍵ファイルは上書きせず、秘密値を標準出力へ
表示しません。Offline端末と暗号化済み媒体で実行してください。

```powershell
cargo run --manifest-path tools/developer-ca-root/Cargo.toml -- root create `
  --private-key C:\offline\root.seed `
  --public-record C:\offline\root-public.json

cargo run --manifest-path tools/developer-ca-root/Cargo.toml -- issuer create `
  --private-key C:\online\intermediate.seed `
  --record C:\offline\issuer.json `
  --not-before 1785100000 --not-after 1816636000 --status active `
  --usage developer-certificate-signing --usage revocation-signing
```

Issuer recordは`--issuer`で1件以上指定します。ローテーション時は同optionを繰り返して
新旧すべてのrecordを渡します。CLIがkey ID順の並べ替えと形式検証を行います。

```powershell
cargo run --manifest-path tools/developer-ca-root/Cargo.toml -- trust-snapshot issue `
  --root-key C:\offline\root.seed --issuer C:\offline\issuer.json `
  --version 1 --generated-at 1785100000 --expires-at 1800652000 `
  --output C:\transfer\trust-v1.json

cargo run --manifest-path tools/developer-ca-root/Cargo.toml -- trust-snapshot verify `
  --snapshot C:\transfer\trust-v1.json `
  --root-public-record C:\offline\root-public.json --at 1785100000
```

Root公開鍵、Root key ID、Online Intermediate seed、Console token鍵をそれぞれ対応する
Worker secretへ設定します。初回migrationだけでは発行されません。署名付きsnapshotを
管理APIへ登録し、失効snapshotをrebuildしてから発行を開始します。

初回登録時はConsole token署名鍵から120秒以内の管理tokenをファイルへ発行します。
`subject`はConsole D1でDeveloperCA reviewerに登録済みのAccount UUIDです。

```powershell
$issuedAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
cargo run --manifest-path tools/developer-ca-root/Cargo.toml -- admin-token issue `
  --signing-key C:\online\console-token.seed `
  --subject 00000000-0000-4000-8000-000000000000 `
  --issued-at $issuedAt --expires-at ($issuedAt + 120) `
  --output C:\transfer\admin.token

$token = (Get-Content -Raw C:\transfer\admin.token).Trim()
Invoke-WebRequest https://ca.mochios.org/v1/admin/trust-snapshots `
  -Method Post -Headers @{ Authorization = "Bearer $token" } `
  -ContentType application/json -InFile C:\transfer\trust-v1.json
```

tokenは1回の重要操作にしか使用できません。失効snapshot rebuildには新しいtokenを発行
してください。使用後のtokenファイルは安全に破棄します。

登録後は公開APIから返ったJSONが入力ファイルとbyte単位で同じであること、ETag、version、
有効期限を確認します。ローテーション時はversionとgenerated_atを必ず増やし、過去Issuer
を省略しません。
