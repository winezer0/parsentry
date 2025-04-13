use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    JavaScript,
    Rust,
    TypeScript,
    Java,
    Go,
    Ruby,
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
            "go" => Language::Go,
            "rb" => Language::Ruby,
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
                r#"async\sdef\s\w+\(.*?request"#,
                r#"@app\.route\(.*?\)"#,
                r#"gr.Interface\(.*?\)"#,
                r#"\bopen\s*\("#,
                r#"\.write\s*\("#,
                r#"\bsubprocess\."#,
                r#"\bos\.system\s*\("#,
                r#"\brequests\."#,
                r#"\bpickle\.load"#,
                r#"\byaml\.load"#,
                r#"\beval\s*\("#,
                r#"\bexec\s*\("#,
                r#"\bsqlite3\."#,
                r#"\bpsycopg2\."#,
                r#"\bsend\s*\("#,
                r#"\bsocket\."#,
                r#"\bsmtplib\."#,
                r#"\bshelve\."#,
                r#"\bparamiko\."#,
                r#"\bftplib\."#,
                r#"\burllib\."#,
                r#"flask\.send_file"#,
                r#"flask\.send_from_directory"#,
            ],
        );
        map.insert(
            JavaScript,
            vec![
                r#"fetch\(.*?\)"#,
                r#"axios\.(get|post|put|delete)"#,
                r#"\beval\s*\("#,
                r#"document\.write\s*\("#,
                r#"\.innerHTML\s*="#,
                r#"setTimeout\s*\(\s*['"]"#,
                r#"setInterval\s*\(\s*['"]"#,
                r#"\bFunction\s*\("#,
                r#"XMLHttpRequest"#,
                r#"WebSocket"#,
                r#"localStorage"#,
                r#"location\s*="#,
                r#"window\.open\s*\("#,
                r#"postMessage\s*\("#,
                r#"\$.ajax\s*\("#,
                r#"require\s*\("#,
                r#"child_process"#,
                r#"fs\.writeFile"#,
                r#"process\.env"#,
                r#"\batob\s*\("#,
                r#"\bbtoa\s*\("#,
            ],
        );
        map.insert(
            Rust,
            vec![
                r#"async\s+fn\s+\w+.*?Request"#,
                r#"#\[.*?route.*?\]"#,
                r#"#\[(get|post|put|delete)\(.*?\)]"#,
                r#"HttpServer::new"#,
                r#"listen\(.*?\)"#,
                r#"bind\(.*?\)"#,
                r#"std::fs::write"#,
                r#"std::fs::File"#,
                r#"std::process::Command"#,
                r#"std::net::TcpStream"#,
                r#"reqwest::"#,
                r#"hyper::"#,
                r#"actix_web::"#,
                r#"rocket::"#,
                r#"std::env::"#,
                r#"std::os::"#,
                r#"std::io::Write"#,
                r#"std::os::unix::process::CommandExt"#,
            ],
        );
        map.insert(
            TypeScript,
            vec![
                r#"app\.(get|post|put|delete)\(.*?\)"#,
                r#"fetch\(.*?\)"#,
                r#"axios\.(get|post|put|delete)"#,
                r#"\beval\s*\("#,
                r#"document\.write\s*\("#,
                r#"\.innerHTML\s*="#,
                r#"setTimeout\s*\(\s*['"]"#,
                r#"setInterval\s*\(\s*['"]"#,
                r#"\bFunction\s*\("#,
                r#"XMLHttpRequest"#,
                r#"WebSocket"#,
                r#"localStorage"#,
                r#"location\s*="#,
                r#"window\.open\s*\("#,
                r#"postMessage\s*\("#,
                r#"\$.ajax\s*\("#,
                r#"require\s*\("#,
                r#"child_process"#,
                r#"fs\.writeFile"#,
                r#"process\.env"#,
                r#"\batob\s*\("#,
                r#"\bbtoa\s*\("#,
            ],
        );
        map.insert(
            Java,
            vec![
                r#"FileWriter"#,
                r#"FileOutputStream"#,
                r#"Runtime\.exec"#,
                r#"ProcessBuilder"#,
                r#"HttpURLConnection"#,
                r#"Socket"#,
                r#"ObjectInputStream"#,
                r#"ScriptEngine"#,
                r#"sendRedirect"#,
                r#"getWriter\s*\("#,
                r#"getOutputStream\s*\("#,
                r#"JDBC"#,
                r#"Files\.write"#,
                r#"Files\.newBufferedWriter"#,
                r#"PrintWriter"#,
                r#"ServletOutputStream"#,
            ],
        );
        map.insert(
            Go,
            vec![
            r#"\bhttp\.HandleFunc\s*\("#,
            r#"\bhttp\.ListenAndServe\s*\("#,
            r#"\bos\.Exec\s*\("#,
            r#"\bos\.StartProcess\s*\("#,
            r#"\bos\.OpenFile\s*\("#,
            r#"\bios\.WriteFile\s*\("#,
            r#"\bnet\.Dial\s*\("#,
            r#"\bnet\.Listen\s*\("#,
            r#"\bjson\.Unmarshal\s*\("#,
            r#"\bxml\.Unmarshal\s*\("#,
            r#"\btemplate\.Must\s*\("#,
            r#"\btemplate\.ParseFiles\s*\("#,
            r#"\bexec\.Command\s*\("#,
            r#"\bexec\.LookPath\s*\("#,
            r#"\bcrypto\/tls"#,
            r#"\bcrypto\/x509"#,
            r#"\bencoding\/gob"#,
            r#"\bencoding\/json"#,
            r#"\bencoding\/xml"#,
            // SQL execution and DB sinks
            r#"\bdb\.Query\s*\("#,
            r#"\bdb\.QueryRow\s*\("#,
            r#"\bdb\.Exec\s*\("#,
            r#"\bdb\.Prepare\s*\("#,
            r#"\bsql\.Open\s*\("#,
            r#"\bsql\.DB"#,
            r#"\bGORM"#,
            r#"\bRaw\s*\("#,
            r#"\bScan\s*\("#,
            // File and network sinks
            r#"\bios\.Create\s*\("#,
            r#"\bios\.Remove\s*\("#,
            r#"\bios\.Rename\s*\("#,
            r#"\bios\.Chmod\s*\("#,
            r#"\bios\.Mkdir\s*\("#,
            r#"\bios\.MkdirAll\s*\("#,
            r#"\bnet\.Conn"#,
            r#"\bnet\.TCPConn"#,
            r#"\bnet\.UDPConn"#,
            // Dangerous reflection and code execution
            r#"\breflect\.Value"#,
            r#"\bruntime\.Caller"#,
            // Email and external communication
            r#"\bnet/smtp"#,
            r#"\bhttp\.Post\s*\("#,
            r#"\bhttp\.PostForm\s*\("#,
            r#"\bhttp\.Get\s*\("#,
            // Unsafe
            r#"\bunsafe\."#,
            ],
        );
        map.insert(
            Ruby,
            vec![
                r#"\beval\s*\("#,
                r#"\bsystem\s*\("#,
                r#"`.*`"#,
                r#"Kernel\.exec"#,
                r#"IO\.popen"#,
                r#"File\.open\s*\("#,
                r#"File\.read\s*\("#,
                r#"File\.write\s*\("#,
                r#"Dir\.glob\s*\("#,
                r#"Net::HTTP"#,
                r#"OpenURI"#,
                r#"Socket"#,
                r#"TCPSocket"#,
                r#"UDPSocket"#,
                r#"Marshal\.load"#,
                r#"YAML\.load"#,
                r#"DBI\.connect"#,
                r#"ActiveRecord::Base\.connection\.execute"#,
                r#"find_by_sql"#,
                r#"params\["#,
                r#"render\s+inline:"#,
                r#"render\s+text:"#,
                r#"send_file"#,
                r#"send_data"#,
                r#"redirect_to"#,
            ],
        );
        map.insert(
            Other,
            vec![
                r#"\beval\s*\("#,
                r#"\bexec\s*\("#,
                r#"system\s*\("#,
                r#"write\s*\("#,
                r#"send\s*\("#,
                r#"open\s*\("#,
            ],
        );

        map
    }
}
