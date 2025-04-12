use crate::response::VulnType;
use std::collections::HashMap;

pub const README_SUMMARY_PROMPT_TEMPLATE: &str = r#"
与えられたREADMEの内容を分析し、以下を簡潔にまとめてください：
- プロジェクトの主目的と機能
- 主要な特徴や能力
- 重要な技術的詳細や要件
- セキュリティに関する情報

<summary></summary> タグ内にまとめてください。
"#;

pub const SYS_PROMPT_TEMPLATE: &str = r#"
あなたはセキュリティ研究者として、コードの脆弱性を分析します。特に以下に注目してください：
- 入力値の検証とサニタイズ
- 認証・認可
- データの取り扱いと漏洩
- コマンドインジェクションの可能性
- パストラバーサルの脆弱性
- その他セキュリティ上重要なパターン

必ず以下のJSON形式で日本語で回答してください:
{
    "scratchpad": "作業メモや思考過程",
    "analysis": "詳細なセキュリティ分析",
    "poc": "概念実証や攻撃手順",
    "confidence_score": 0-100,
    "vulnerability_types": ["LFI", "RCE", "SSRF", "AFO", "SQLI", "XSS", "IDOR"],
    "context_code": [
        {
            "name": "関数やブロック名",
            "reason": "このコードが脆弱性に関係する理由",
            "code_line": "該当するコード行"
        }
    ]
}

READMEサマリーの内容も考慮して分析してください。
"#;

pub const INITIAL_ANALYSIS_PROMPT_TEMPLATE: &str = r#"
与えられたコードをセキュリティ脆弱性の観点から分析してください。特に以下を考慮してください：
- ユーザー入力の取り扱いと検証
- 認証・認可の仕組み
- データのサニタイズやエスケープ
- ファイルシステム操作
- ネットワークリクエストとレスポンス
- コマンド実行
- データベースクエリ

必ず以下のJSON形式で日本語で回答してください:
{
    "scratchpad": "分析の手順や作業メモ",
    "analysis": "詳細な発見内容と脆弱性の説明",
    "poc": "具体的な概念実証や攻撃手順",
    "confidence_score": 0-100,
    "vulnerability_types": ["LFI", "RCE", "SSRF", "AFO", "SQLI", "XSS", "IDOR"],
    "context_code": [
        {
            "name": "関数やブロック名",
            "reason": "このコードが脆弱性に関係する理由",
            "code_line": "該当する脆弱なコード行"
        }
    ]
}

※ vulnerability_typesは上記のいずれか（複数可）を必ず使用してください。
"#;

pub const ANALYSIS_APPROACH_TEMPLATE: &str = r#"
以下の手順で分析を進めてください：
1. エントリポイントとユーザーが制御可能な入力を特定する
2. アプリケーション内のデータフローを追跡する
3. セキュリティ上重要な操作を調査する
4. 既存の防御策を回避する手法（バイパス）を検討する
5. 潜在的な脆弱性の影響を評価する
"#;

pub const GUIDELINES_TEMPLATE: &str = r#"
以下のガイドラインを遵守してください：
1. 実際に悪用可能な脆弱性に絞って分析する
2. 該当するコード箇所や行番号を具体的に示す
3. アプリケーション全体の文脈を考慮する
4. コードの可視性や分析の深さに応じて信頼度を評価する
5. より良い分析のために追加情報が必要な場合はリクエストする
"#;

pub mod vuln_specific {
    use super::*;

    pub struct VulnTypeInfo {
        pub prompt: String,
        pub bypasses: Vec<String>,
    }

    pub fn get_vuln_specific_info() -> HashMap<VulnType, VulnTypeInfo> {
        let mut map = HashMap::new();

        map.insert(
            VulnType::LFI,
            VulnTypeInfo {
                prompt: "ローカルファイルインクルージョン（LFI）の脆弱性が存在しないか分析してください。".to_string(),
                bypasses: vec![
                    "パストラバーサルシーケンス（../../ など）".to_string(),
                    "URLエンコーディングによるバイパス".to_string(),
                    "ヌルバイトインジェクション".to_string(),
                ],
            },
        );

        map.insert(
            VulnType::RCE,
            VulnTypeInfo {
                prompt: "リモートコード実行（RCE）の脆弱性が存在しないか分析してください。"
                    .to_string(),
                bypasses: vec![
                    "シェルメタ文字によるコマンドインジェクション".to_string(),
                    "Pythonコード実行ベクトル".to_string(),
                    "デシリアライズ攻撃".to_string(),
                ],
            },
        );

        map.insert(
            VulnType::SSRF,
            VulnTypeInfo {
                prompt: "Analyze for Server-Side Request Forgery vulnerabilities...".to_string(),
                bypasses: vec![
                    "DNSリバインディング攻撃".to_string(),
                    "IPアドレスのエンコーディングトリック".to_string(),
                    "リダイレクトチェーン".to_string(),
                ],
            },
        );

        map.insert(
            VulnType::AFO,
            VulnTypeInfo {
                prompt: "Analyze for Arbitrary File Operation vulnerabilities...".to_string(),
                bypasses: vec![
                    "ディレクトリトラバーサルシーケンス".to_string(),
                    "シンボリックリンクの追従".to_string(),
                    "競合状態（レースコンディション）".to_string(),
                ],
            },
        );

        map.insert(
            VulnType::SQLI,
            VulnTypeInfo {
                prompt: "Analyze for SQL Injection vulnerabilities...".to_string(),
                bypasses: vec![
                    "UNIONベースのインジェクション".to_string(),
                    "ブール型ブラインドインジェクション".to_string(),
                    "時間差ブラインドインジェクション".to_string(),
                ],
            },
        );

        map.insert(
            VulnType::XSS,
            VulnTypeInfo {
                prompt: "Analyze for Cross-Site Scripting vulnerabilities...".to_string(),
                bypasses: vec![
                    "HTMLエンティティエンコーディングによるバイパス".to_string(),
                    "JavaScriptテンプレートインジェクション".to_string(),
                    "DOMベースのXSSベクトル".to_string(),
                ],
            },
        );

        map.insert(
            VulnType::IDOR,
            VulnTypeInfo {
                prompt: "Analyze for Insecure Direct Object Reference vulnerabilities..."
                    .to_string(),
                bypasses: vec![
                    "パラメータ改ざん".to_string(),
                    "水平的な権限昇格".to_string(),
                    "予測可能なリソースパス".to_string(),
                ],
            },
        );

        map
    }
}
