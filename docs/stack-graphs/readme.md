# Stack Graphs Documentation

1. [Core Concepts](./concepts.md)
   - 基本アーキテクチャ
   - Name Binding Structure
   - Stack System
   - Graph Structure
   - Scope Graphsとの関係
   - Tree-sitter統合

2. [Core Components](./components.md)
   - StackGraph
   - LanguageConfiguration
   - Loader
   - StackGraphLanguage
   - Variables
   - NoCancellation
   - Definition
   - SQLiteWriter

3. [Use Cases and References](./examples/readme.md)
   - IDE Integration
     - Definition Jump / 定義ジャンプ
     - Reference Search / 参照検索
     - Code Completion / コード補完
   - Static Analysis
     - Unused Variable Detection / 未使用変数検出
     - Name Collision Check / 名前衝突チェック
   - Refactoring Support
     - Safe Renaming / リネーム
     - Impact Analysis / 影響分析

## Quick Start

Stack Graphsを使用するには、以下のドキュメントを順に参照することをお勧めします：

1. まず[Core Concepts](./concepts.md)で基本的な概念とアーキテクチャを理解
2. [Core Components](./components.md)で各コンポーネントの詳細な実装を学習
3. [Use Cases and References](./examples/readme.md)で実際の応用例を確認

## Contributing

Stack Graphsの開発に貢献するには、以下のリソースを参照してください：

- [GitHub Repository](https://github.com/github/stack-graphs)
- [Issue Tracker](https://github.com/github/stack-graphs/issues)
- [Contributing Guidelines](https://github.com/github/stack-graphs/blob/main/CONTRIBUTING.md)

## License

Stack Graphsは[MIT License](https://github.com/github/stack-graphs/blob/main/LICENSE)の下で公開されています。
