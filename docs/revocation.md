# 失効

管理者は登録済み証明書だけを失効できます。D1の失効記録は監査とAppStoreのオンライン確認に使います。

mochiOSの権威ある失効判定はオンラインCRL／OCSPではなく、OS imageへ組み込んだserial一覧です。DeveloperCAの`GET /v1/revocations`からserialを取得し、`signature.service`のbuild時に`MOCHIOS_REVOKED_CERTIFICATE_SERIALS`へ反映してOSを更新します。

失効済みserialを再利用してはいけません。
