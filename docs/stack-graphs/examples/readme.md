# Stack Graphs Use Cases and References

Stack Graphsの実際の応用例

## Use Cases

### 1. [IDE Integration（IDE統合）](./ide_integration.rs)

- シンボル検索の実装
  - 参照の検索（並列処理とキャッシュを活用）
  - 定義の検索（スコープ解決を含む）
- コード補完
  - ローカルスコープの候補収集
  - インポート済み候補の収集
  - 型情報に基づく候補生成

### 2. [Static Analysis（静的解析）](./static_analysis.rs)

- 未使用変数の検出
  - 変数の使用状況収集
  - 設定に基づくフィルタリング
  - クイックフィックスの生成
- 名前の衝突チェック
  - スコープベースの分析
  - 衝突の重要度判定
  - 解決策の提案

### 3. [Refactoring Support（リファクタリングサポート）](./refactoring_support.rs)

- 安全なリネーム
  - 影響範囲の分析
  - 変更の検証
  - インデックスの更新
- 影響分析
  - 直接的な影響の分析
  - 間接的な影響の分析
  - リスクレベルの評価
