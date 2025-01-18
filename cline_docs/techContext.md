# Technical Context

## 使用技術

### 言語とフレームワーク
- Rust: メインの開発言語
- Tree-sitter: コードパース用ライブラリ
- Stack Graphs: コード解析とグラフ構築
- GPT API: AIによる脆弱性分析

### 主要な依存関係
```toml
anyhow = "エラーハンドリング"
genai = "GPT APIクライアント"
log = "ロギング"
regex = "正規表現"
serde = "シリアライズ/デシリアライズ"
```

### サポート言語
1. Python (tree-sitter-python)
2. Rust (tree-sitter-rust)
3. JavaScript (tree-sitter-javascript)
4. TypeScript (tree-sitter-typescript)
5. Java (tree-sitter-java)
6. Go (tree-sitter-go)

## 開発環境セットアップ

### 必要条件
1. Rust toolchain (rustc, cargo)
2. GPT API キー
3. Tree-sitter CLI (オプション)

### ビルド手順
```bash
# 依存関係のインストール
cargo build

# テストの実行
cargo test

# スナップショットテストの実行
cargo test --features snapshot-test
```

## 技術的制約

### パフォーマンス
1. GPT APIのレスポンス時間
2. 大規模コードベースの解析時間
3. メモリ使用量の制限

### スケーラビリティ
1. 並列処理の制限
2. APIレート制限の考慮
3. ファイルサイズの制限

### セキュリティ
1. APIキーの保護
2. ファイルアクセスの制限
3. 出力の検証

## デプロイメント考慮事項

### 環境変数
1. OPENAI_API_KEY
2. LOG_LEVEL
3. RUST_BACKTRACE

### リソース要件
1. メモリ: 最小512MB推奨
2. ストレージ: プロジェクトサイズに依存
3. CPU: マルチコア推奨
