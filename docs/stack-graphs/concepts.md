# Stack Graphs Core Concepts

Stack Graphsは、プログラミング言語の名前解決 rulesを効率的に定義・実装するためのframeworkです。このドキュメントでは、Stack Graphsの基本概念とアーキテクチャについて説明する。

## 基本アーキテクチャ

Stack Graphsは、name bindingをgraphとして表現し、path探索によって名前解決を実現する。このフレームワークは、任意のプログラミング言語の名前解決を単一の枠組みで実現しながら、各言語固有の名前解決ルールを抽象化する。

### Name Binding Structure

- **Definitions and References**
  - Name bindingをgraphとして表現
  - 各bindingは可能な定義へのpathとして表現
  - Definitionは変数、関数、クラスなどのシンボルの宣言位置
  - Referenceはそれらのシンボルが使用される位置

- **Path Resolution**
  - Graphのpath探索によって名前解決
  - Incremental stack graphによる効率的な探索
  - 前方解析（定義から参照）と後方解析（参照から定義）の両方をサポート

### Stack System

- **Symbol Stack**
  - 現在解決中のsymbolを追跡
  - Symbol間の依存関係を管理
  - Binding構造のtraverseに使用
  - シンボルの優先順位と可視性を制御
  - 循環参照の検出と処理

- **Scope Stack**
  - 現在のscope contextを管理
  - Lexical scopingの実装
  - Scope階層の制御
  - ネストされたスコープの解決
  - スコープチェーンの構築と探索

### Graph Structure

1. **Node Types**
   - Push Nodes: scopeをstackにpush
     - スコープの開始を表現
     - 新しいコンテキストの作成
     - 変数の可視性範囲の制御
   - Pop Nodes: stackからscopeをpop
     - スコープの終了を表現
     - コンテキストの復元
     - スコープチェーンの管理
   - Scope Nodes: lexical scopeを表現
     - スコープの境界を定義
     - 変数の有効範囲を管理
     - 親子関係の表現
   - Symbol Nodes: 変数、関数、classなどの名前を表現
     - シンボルの種類（変数、関数、クラスなど）
     - シンボルの属性（可視性、型情報など）
     - シンボルの位置情報

2. **Edge Types**
   - Scope Edges: lexical scopeの関係を表現
     - スコープ間の階層関係
     - 継承関係
     - モジュール間の依存関係
   - Symbol Edges: 定義と参照を接続
     - シンボルの使用関係
     - 型の依存関係
     - インポート/エクスポート関係

## Relationship to Scope Graphs

Stack GraphsはScope Graphsを拡張したframeworkです：

1. **Enhanced Resolution**
   - Stack-based 名前解決
   - より柔軟なbinding rule
   - Cross-language resolution support

2. **Incremental Processing**
   - Partial graph updates
   - File-level granularity
   - Efficient re-analysis

## Tree-sitter Integration

Tree-sitter Stack Graphsは、Tree-sitter parserとStack Graphsを統合したツールです：

### Key Features

- Tree-sitterによる高速な構文解析
- Graph DSLによるstack graphの構築
- Multiple language support
  - Python
  - JavaScript
  - TypeScript
  - Java
