# Testing Guide

## テスト戦略

1. Unit Test
   - 個々のコンポーネントの機能を検証
   - `src/`内の各moduleに`tests` moduleとして実装
   - 例：`parser::tests`でのparse処理のテスト

2. Snapshot Test
   - 非決定的な応答を含むコンポーネントの検証
   - `snapshot-test` featureで制御
   - 例：GPTモデルを使用した脆弱性分析のテスト

3. Integration Test
   - 複数のコンポーネントの連携を検証
   - 実際のfile systemやAPIを使用
   - 例：parserと analyzerの連携テスト

## テストの実行

```bash
# 一般的なテスト
cargo test

# snapshot testを含むすべてのテスト
cargo test --features snapshot-test

# 特定のテストの実行
cargo test test_name --features snapshot-test
```

## テストの実装方針

### 1. Module levelのテスト

各source fileには対応するtest moduleを実装します：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_specific_function() {
        // テストの実装
    }
}
```

### 2. 非決定的な応答のテスト

外部serviceや非決定的な応答を含むテストでは、以下の方針を採用：

1. 構造的な検証
   - 応答のformatや必須fieldの存在を確認
   - 具体的な値ではなく、値のtypeや存在を検証

2. 堅牢なassertion
   - 明確なerror messageを含む
   - 失敗時の原因特定が容易

3. 段階的な検証
   - 単純なcaseから複雑なcaseへ
   - 独立したassertionの使用

### 3. Test dataの管理

1. Fixture (TODO)
   - `tests/fixtures/`directoryにtest dataを配置
   - 再利用可能なtest caseの管理

2. Snapshot
   - `snapshots/`directoryに保存
   - `cargo insta review`で管理
