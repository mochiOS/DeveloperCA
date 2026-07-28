# 信頼モデル

Developer CertificateはRootが直接署名します。mochiOSは信頼するRoot公開鍵をOS imageへ組み込み、MCER v1のissuer key IDと署名を照合します。GitHub、DeveloperCA、AppStoreへ保存されていること自体は信頼根拠ではありません。

Root秘密鍵はオフライン環境の`msign`だけで使用します。Cloudflare Worker、D1、CI、開発者ブラウザーへ配布しません。Root公開鍵の変更はOS更新として扱います。
