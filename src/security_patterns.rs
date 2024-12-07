use regex::Regex;

/// Patterns to detect potentially vulnerable network-related code
/// such as HTTP request handlers, API routes, and network interfaces
#[derive(Default)]
pub struct SecurityRiskPatterns {
    patterns: Vec<Regex>,
}

impl SecurityRiskPatterns {
    pub fn new() -> Self {
        let patterns = vec![
            // Python patterns
            r"async\sdef\s\w+\(.*?request", // Async request handlers
            r"@app\.route\(.*?\)",          // Flask routes
            r"gr.Interface\(.*?\)",         // Gradio interfaces
            // JavaScript/TypeScript patterns
            r"app\.(get|post|put|delete)\(.*?\)", // Express.js routes
            r"fetch\(.*?\)",                      // Fetch API calls
            r"axios\.(get|post|put|delete)",      // Axios HTTP calls
            // Rust patterns
            r"async\s+fn\s+\w+.*?Request", // Async request handlers
            r"#\[.*?route.*?\]",           // Route attributes
            r"#\[(get|post|put|delete)\(.*?\)]", // Actix-web route attributes
            r"HttpServer::new",            // HTTP server initialization
            // Generic patterns
            r"listen\(.*?\)", // Network listeners
            r"bind\(.*?\)",   // Socket bindings
        ]
        .into_iter()
        .map(|p| Regex::new(p).unwrap())
        .collect();

        Self { patterns }
    }

    pub fn matches(&self, content: &str) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.is_match(content))
    }
}
