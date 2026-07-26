# セキュリティ

Accounts introspection、membership／role確認、管理API分離、定数時間token比較、
prepared statement、D1 transaction、厳格なCertificate parsing、公開鍵検証、
serial一意制約、追記専用監査ログ、最後のowner保護を実装しています。

秘密鍵とtokenはWorker secretからのみ読み込み、D1、ログ、trust store、Certificate
レスポンスへ出力しません。通常Sessionをservice tokenやadmin tokenとして受理しません。

ConsoleのBFF経路では`CONSOLE_SERVICE_TOKEN`を定数時間比較し、受け取ったAccount IDを
Accountsへ問い合わせてactive状態をfail closedで再確認します。管理APIはこの認証方式を
受理しません。
