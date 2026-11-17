# edge-session-crypto (日本語ドキュメント)

Edge、Cloudflare Workers、Node.js 向けのステートレス暗号化 Cookie セッション管理ライブラリ。ネイティブ WebCrypto (AES-256-GCM + PBKDF2-SHA256) を採用し、外部ランタイム依存ゼロ（Zero Runtime Dependencies）で動作します。

## セキュリティ互換性と移行

- セッション期限の時計許容差は既定で0になりました。期限時刻ちょうどにセッションを拒否します。環境間の時計ずれが実測されている場合は、`unsealData` に `clockTolerance` を明示してください。必要性を定義せず許容差を増やさないでください。

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

## 関連エッジセキュリティパッケージ群

- [wasm-crypto-hash](https://github.com/takao-dev/wasm-crypto-hash): 超高速 WebAssembly & WebCrypto 暗号化スイート (SHA-2/3, BLAKE3, PQC, Argon2, TOTP, BIP-39)
- [edge-rate-limiter](https://github.com/takao-dev/edge-rate-limiter): 外部依存ゼロの固定/スライド窓型レートリミッター（ソルト付き匿名化対応）
- [edge-secure-token](https://github.com/takao-dev/edge-secure-token): タイミング攻撃耐性を持つ WebCrypto ベースの JWT & クレーム暗号化スイート
- [zero-pii-redactor](https://github.com/takao-dev/zero-pii-redactor): ログ・AIプロンプト向けの超高速・ReDoSフリー PII マスキング＆匿名化ツール
- [webcrypto-secure-storage](https://github.com/takao-dev/webcrypto-secure-storage): AES-GCM & HMAC による改ざん検知機能付きセキュアKVストレージ
- [edge-audit-crypto](https://github.com/takao-dev/edge-audit-crypto): 暗号論的ハッシュチェーンによる改ざん耐性監査ログ記録

---

## ライセンス

MIT License
