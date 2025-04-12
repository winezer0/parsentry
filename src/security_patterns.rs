use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    JavaScript,
    Rust,
    TypeScript,
    Java,
    Other,
}

impl Language {
    pub fn from_extension(ext: &str) -> Self {
        match ext {
            "py" => Language::Python,
            "js" => Language::JavaScript,
            "rs" => Language::Rust,
            "ts" => Language::TypeScript,
            "java" => Language::Java,
            _ => Language::Other,
        }
    }
}

pub struct SecurityRiskPatterns {
    patterns: Vec<Regex>,
}

impl SecurityRiskPatterns {
    /// 言語ごとのSecurityRiskPatternsインスタンスを生成する。
    pub fn new(language: Language) -> Self {
        let pattern_map = Self::pattern_map();
        let patterns = pattern_map
            .get(&language)
            .or_else(|| pattern_map.get(&Language::Other))
            .unwrap()
            .iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();

        Self { patterns }
    }

    /// 内容がいずれかのセキュリティリスクパターンに一致すればtrueを返す。
    pub fn matches(&self, content: &str) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.is_match(content))
    }

    /// 言語ごとのパターン定義
    fn pattern_map() -> HashMap<Language, Vec<&'static str>> {
        use Language::*;
        let mut map = HashMap::new();

        map.insert(
            Python,
            vec![
                r"async\sdef\s\w+\(.*?request",
                r"@app\.route\(.*?\)",
                r"gr.Interface\(.*?\)",
            ],
        );
        map.insert(
            JavaScript,
            vec![r"fetch\(.*?\)", r"axios\.(get|post|put|delete)"],
        );
        map.insert(
            Rust,
            vec![
                r"async\s+fn\s+\w+.*?Request",
                r"#\[.*?route.*?\]",
                r"#\[(get|post|put|delete)\(.*?\)]",
                r"HttpServer::new",
                r"listen\(.*?\)",
                r"bind\(.*?\)",
            ],
        );
        map.insert(TypeScript, vec![r"app\.(get|post|put|delete)\(.*?\)"]);
        map.insert(
            Java,
            vec![
                // Java用パターンをここに追加
            ],
        );
        map.insert(
            Other,
            vec![
                // 共通パターンやその他言語用
            ],
        );

        map
    }
}
