use regex::Regex;

#[derive(Default)]
pub struct SecurityRiskPatterns {
    patterns: Vec<Regex>,
}

impl SecurityRiskPatterns {
    /// SecurityRiskPatternsインスタンスを生成する。
    pub fn new() -> Self {
        let patterns = vec![
            r"async\sdef\s\w+\(.*?request",
            r"@app\.route\(.*?\)",
            r"gr.Interface\(.*?\)",
            r"app\.(get|post|put|delete)\(.*?\)",
            r"fetch\(.*?\)",
            r"axios\.(get|post|put|delete)",
            r"async\s+fn\s+\w+.*?Request",
            r"#\[.*?route.*?\]",
            r"#\[(get|post|put|delete)\(.*?\)]",
            r"HttpServer::new",
            r"listen\(.*?\)",
            r"bind\(.*?\)",
        ]
        .into_iter()
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
}
