# Package scopeとCapability Policy

Consoleは`.mpkg`内の`manifest.toml`から次を自動入力します。

```text
[package].id          -> requested Package ID scope
[[binary]].requires[] -> requested Capabilityの和集合
```

発行値は申請値をそのまま採用せず、次の全条件を満たす場合だけ申請全体を発行します。

```text
Package scope = requested ∩ active Developer package-scope grant
Capability    = requested ∩ active Developer capability grant ∩ active global capability
```

1件でも外れる場合は縮小発行せず、申請全体を拒否します。審査画面には不足grantを表示し、
審査者がDeveloper許可とglobal許可を別々に操作します。申請後にgrant、Developer、member
roleが変更された場合も、発行直前とD1保存batch内の再検証で拒否します。
