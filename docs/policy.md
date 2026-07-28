# 証明書ポリシー

- 発行可: active Accountかつactive owner／admin／developer Member
- 一覧・取得可: active Member（viewerを含む）
- Developer条件: `status=active`かつ`verification_status=verified`
- Package scope: Consoleが抽出したPackage IDへの完全一致1件
- Capability: Consoleが抽出した全`[[binary]].requires`の和集合
- Certificate審査: なし
- 管理者操作: 失効のみ
- body上限: 16 KiB
- Capability上限: 512
- 有効期限上限: 1年かIssuer期限まで
- 発行制限: Account 20件/時、Developer 20件/時、Subject key 10件/時
- 同一内容: 同時実行と5分以内は既存Certificateを返す

prefix scopeを一般Developerが指定するUIや、Account IDをrequest bodyからactorとして受け取るAPIはありません。
