# 運用

1. オフライン環境でmochiOSの`tools/devkit/crates/msign`を使用し、Root直署名MCER v1を発行します。
2. 開発者へMCERファイルと、対応するsubject秘密鍵を安全に引き渡します。Root秘密鍵は引き渡しません。
3. 開発者はConsoleからMCERファイルを登録します。
4. AppStore reviewerはMPKG内の`signatures/developer.cert`をRoot公開鍵で検証します。
5. 失効時はConsoleの管理画面で証明書を失効し、serial一覧を次回のOS imageへ反映します。

具体的な`msign`コマンドとファイル形式はmochiOSの`docs/certificates.md`、`docs/mpkg.md`、`docs/packages.md`を正本とします。Root鍵操作はネットワークから隔離した端末で行い、バックアップ媒体とアクセス記録を管理します。
