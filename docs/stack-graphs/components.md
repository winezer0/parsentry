# Core Components

StackGraphの各componentは名前解決とsymbol解析の特定の側面を処理するように設計される。

## StackGraph

[stack-graphs](https://docs.rs/stack-graphs/)はソースコードの名前解決のための基本的なgraph構造です：

- ソースコードの構造をグラフとして表現
- シンボル間の関係性を追跡
- 名前解決のためのパス探索を実行

### 実装例

```rust
let mut graph = StackGraph::new();
let file_id = graph.get_or_create_file("example.py");
```

### Node Types

Node Typesは名前解決における特定の目的を持つ：

1. `scope`
   - デフォルトのnode type
   - lexicalなscopingの境界を表現
   - `is_exported` attributeでexport指定が可能

2. `push_symbol`
   - symbol参照を表現
   - `symbol` attributeが必要
   - `is_reference` attributeで参照指定が可能

3. `pop_symbol`
   - symbol定義を表現
   - `symbol` attributeが必要
   - `is_definition` attributeで定義指定が可能

4. `push_scoped_symbol`
   - scope付きsymbol参照を表現
   - `symbol`と`scope` attributeが必要
   - scopeはexportされたnodeを参照する必要がある

5. `pop_scoped_symbol`
   - scope付きsymbol定義を表現
   - `symbol` attributeが必要
   - 定義として指定可能

6. `drop_scopes`
   - scope操作に使用
   - stackからすべてのscopeを削除
   - スコープチェーンのリセットに使用

### エッジの優先順位

エッジには`precedence`属性を設定でき、これにより名前解決時の優先順位を制御可能：

```rust
// 優先順位の高いエッジの例
edge def -> body attr (def -> body) precedence = 1
```

## StackGraphLanguage

[StackGraphLanguage](https://docs.rs/tree-sitter-stack-graphs/latest/tree_sitter_stack_graphs/struct.StackGraphLanguage.html)は言語固有のstack graph構築ルールを管理。

- 言語固有の構文解析ルールの定義
- Tree-sitterとの統合
- グラフ構築ルールの管理

### 実装例

```rust
// 言語設定の取得
fn get_language_configurations(language: &str) -> Vec<LanguageConfiguration> {
    match language.to_lowercase().as_str() {
        "python" => vec![tree_sitter_stack_graphs_python::language_configuration(
            &NoCancellation,
        )],
        "javascript" => vec![tree_sitter_stack_graphs_javascript::language_configuration(
            &NoCancellation,
        )],
        // 他の言語サポートを追加可能
        _ => vec![],
    }
}

// 言語設定の使用
let mut language = StackGraphLanguage::from_str(grammar, rules)?;
```

## Variables

[Variables](https://docs.rs/tree-sitter-stack-graphs/latest/tree_sitter_stack_graphs/struct.Variables.html)はstack graph構築のための不変なvariable環境です。

- グラフ構築時の変数管理
- 不変性による安全性の保証
- スレッド安全な変数環境の提供

### 使用例

```rust
let globals = Variables::new();
language.build_stack_graph_into(
    &mut stack_graph,
    file_id,
    source_code,
    &globals,
    &NoCancellation
)?;
```

## NoCancellation

[NoCancellation](https://docs.rs/tree-sitter-stack-graphs/latest/tree_sitter_stack_graphs/struct.NoCancellation.html)はシンプルなnon-cancellable実行contextです。

### 用途

- グラフ構築処理のキャンセル制御
- 長時間実行の制御
- エラーハンドリングの簡素化

## Loader

[Loader](https://docs.rs/tree-sitter-stack-graphs/latest/tree_sitter_stack_graphs/loader/index.html)はstack graph言語のファイル読み込みと解析用のモジュールです。

- ソースファイルの読み込み
- 言語設定の適用
- グラフの構築と保存

### 実装例

```rust
let loader = Loader::from_language_configurations(
    language_configurations,
    None
).expect("Expected loader");
```

## データベース統合

stack-graphsはSQLiteを使用してグラフデータを永続化する：

```rust
// インメモリデータベース
let db_writer = SQLiteWriter::open_in_memory()
    .map_err(|e| format!("Failed to create in-memory database: {}", e))?;

// ファイルベースのデータベース
let db_writer = SQLiteWriter::open(path)
    .map_err(|e| format!("Failed to open database: {}", e))?;
```

## エラーハンドリング

```rust
#[derive(Debug, Clone)]
pub struct StackGraphsError {
    message: String,
}

impl StackGraphsError {
    pub fn from(message: String) -> StackGraphsError {
        StackGraphsError { message }
    }
}

// エラーハンドリングの例
pub fn add_file(&mut self, path: &Path) -> Result<(), StackGraphsError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| StackGraphsError::from(format!("Failed to read file: {}", e)))?;

    // グラフ構築時のエラーハンドリング
    language.build_stack_graph_into(/*...*/)
        .map_err(|e| StackGraphsError::from(format!("Failed to build stack graph: {}", e)))?;

    Ok(())
}
