# edge-session-crypto (日本語ドキュメント)

Edge、Cloudflare Workers、Node.js 向けのステートレス暗号化 Cookie セッション管理ライブラリ。ネイティブ WebCrypto (AES-256-GCM + PBKDF2-SHA256) を採用し、外部ランタイム依存ゼロ（Zero Runtime Dependencies）で動作します。

---

## 主な特長

1. **完全ステートレス & DB 不要**:
   - クライアントの Cookie 内に AES-GCM で暗号化＋改ざん検知署名を施して保存する「Sealed Cookie パターン」。Redis やデータベースが不要です。
2. **外部依存ゼロ (Zero Runtime Dependencies)**:
   - Web 標準の WebCrypto `SubtleCrypto` のみで実装されており、軽量でサプライチェーンリスクがありません。
3. **安全なキーローテーション**:
   - パスワード配列 (`[newKey, oldKey]`) を渡すだけで、旧鍵で暗号化された既存セッションの復号と新鍵への段階的移行を透過的に処理。
4. **モダン Cookie セキュリティ標準**:
   - `HttpOnly`, `Secure`, `SameSite=Lax`, CHIPS (`Partitioned`) 属性を標準サポート。

---

## ライセンス

MIT License
