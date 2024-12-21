use log::{debug, trace};
use std::path::{Path, PathBuf};

use crate::parser::{CodeParser, Definition};

#[derive(Debug)]
pub struct CodeDefinition {
    pub name: String,
    pub context_name_requested: String,
    pub file_path: PathBuf,
    pub source: String,
}

pub struct SymbolExtractor {
    parser: CodeParser,
}

impl SymbolExtractor {
    pub fn new<P: AsRef<Path>>(_root_path: P) -> Self {
        Self {
            parser: CodeParser::new().expect("Failed to initialize parser"),
        }
    }

    pub fn extract(
        &mut self,
        name: &str,
        code_line: &str,
        files: &[PathBuf],
    ) -> Option<CodeDefinition> {
        debug!(
            "Extracting definition for name: {} code_line: {}",
            name, code_line
        );

        for file_path in files {
            debug!("Processing file: {}", file_path.display());

            if let Ok(definitions) = self.parser.parse_file(file_path) {
                debug!("Found {} definitions in file", definitions.len());
                trace!("Definitions: {:?}", definitions);

                // まず関数定義を検索
                if let Some(def) =
                    self.find_function_definition(&definitions, name, code_line, file_path)
                {
                    debug!("Found function definition");
                    return Some(def);
                }

                // 次に脆弱性パターンを検索
                if let Some(def) =
                    self.find_vulnerability_pattern(&definitions, name, code_line, file_path)
                {
                    debug!("Found vulnerability pattern");
                    return Some(def);
                }

                // 最後に一般的なパターンを検索
                if let Some(def) =
                    self.find_general_pattern(&definitions, name, code_line, file_path)
                {
                    debug!("Found general pattern");
                    return Some(def);
                }
            }
        }

        debug!("No matching definition found");
        None
    }

    fn find_function_definition(
        &self,
        definitions: &[Definition],
        name: &str,
        code_line: &str,
        file_path: &Path,
    ) -> Option<CodeDefinition> {
        debug!("Searching for function definition: {}", name);

        for def in definitions {
            trace!("Checking definition: {:?}", def);

            // 関数名とFlaskルートの定義を確認
            let clean_name = name
                .replace("\\", "")
                .replace("()", "")
                .replace(" function", "")
                .replace(" endpoint", "");

            let name_variations = vec![
                clean_name.clone(),
                format!("function.name - {}", clean_name),
                format!("method.name - {}", clean_name),
                format!("route - {}", clean_name),
                format!("@app.route - {}", clean_name),
                format!("def {}", clean_name),
                if clean_name.starts_with("/") {
                    clean_name[1..].to_string()
                } else {
                    clean_name.clone()
                },
                clean_name.replace("function", ""),
                clean_name.replace("route", ""),
                clean_name.replace("vulnerability", ""),
                clean_name.replace("Injection", ""),
                clean_name.replace("Point", ""),
                clean_name.replace("Declaration", ""),
                clean_name.replace("Handling", ""),
                clean_name.replace("construction", ""),
                clean_name.replace("in ", ""),
                clean_name.replace("Line ", ""),
                clean_name.replace("def ", ""),
                if clean_name.contains("Template") || name.contains("template") {
                    "render_template_string".to_string()
                } else {
                    clean_name.clone()
                },
                if clean_name.contains("SQL") || name.contains("sql") {
                    "execute".to_string()
                } else {
                    clean_name.clone()
                },
                if clean_name.contains("Command") || name.contains("command") {
                    "popen".to_string()
                } else {
                    clean_name.clone()
                },
                if clean_name.contains("Output") || name.contains("output") {
                    "render".to_string()
                } else {
                    clean_name.clone()
                },
                if clean_name.contains("input") || name.contains("Input") {
                    "request.args.get".to_string()
                } else {
                    clean_name.clone()
                },
            ];

            if name_variations
                .iter()
                .any(|variant| def.name.contains(variant))
            {
                if let Ok(source) = self.parser.get_definition_source(file_path, def) {
                    trace!("Found source: {}", source);
                    if source.contains(code_line) {
                        debug!("Found matching function definition");
                        return Some(CodeDefinition {
                            name: name.to_string(),
                            context_name_requested: name.to_string(),
                            file_path: file_path.to_path_buf(),
                            source,
                        });
                    }
                }
            }
        }
        None
    }

    fn find_vulnerability_pattern(
        &self,
        definitions: &[Definition],
        pattern_name: &str,
        code_line: &str,
        file_path: &Path,
    ) -> Option<CodeDefinition> {
        debug!("Searching for vulnerability pattern: {}", pattern_name);
        let pattern_type = pattern_name.to_lowercase();

        // 脆弱性タイプに基づいてパターンを選択
        let relevant_patterns: Vec<&str> = if pattern_type.contains("sql") {
            vec!["sql.call", "sql.exec", "sql.method"]
        } else if pattern_type.contains("command") || pattern_type.contains("rce") {
            vec![
                "cmd.call",
                "cmd.exec",
                "cmd.method",
                "cmd.object",
                "cmd.arg",
                "vuln.object - os",
                "vuln.object - subprocess",
                "vuln.method - system",
                "vuln.method - run",
                "vuln.method - exec",
                "vuln.method - spawn",
                "vuln.method - popen",
            ]
        } else if pattern_type.contains("xss") || pattern_type.contains("template") {
            vec![
                "dom.method - innerHTML",
                "dom.method - outerHTML",
                "dom.method - write",
                "dom.method - writeln",
                "dom.method - insertAdjacentHTML",
                "vuln.method - render",
                "vuln.method - template",
                "vuln.method - html",
                "vuln.object - document",
                "vuln.property - innerHTML",
                "vuln.property - outerHTML",
                "render_template",
                "render_template_string",
                "jinja2.Template",
                "format",
                "f-string",
                "str.format",
                "template.render",
                "template.compile",
                "template.format",
                "vuln.method - render",
                "vuln.method - template",
                "vuln.method - format",
                "vuln.method - eval",
            ]
        } else {
            vec![]
        };

        debug!("Relevant patterns: {:?}", relevant_patterns);

        for def in definitions {
            trace!("Checking definition: {:?}", def);

            let def_name_lower = def.name.to_lowercase();
            if relevant_patterns
                .iter()
                .any(|&pattern| def_name_lower.contains(pattern))
            {
                if let Ok(source) = self.parser.get_definition_source(file_path, def) {
                    trace!("Found source: {}", source);
                    if source.contains(code_line) {
                        debug!("Found matching vulnerability pattern");
                        return Some(CodeDefinition {
                            name: def.name.clone(),
                            context_name_requested: pattern_name.to_string(),
                            file_path: file_path.to_path_buf(),
                            source,
                        });
                    }
                }
            }
        }
        None
    }

    fn find_general_pattern(
        &self,
        definitions: &[Definition],
        name: &str,
        code_line: &str,
        file_path: &Path,
    ) -> Option<CodeDefinition> {
        debug!("Searching for general pattern");
        let name_lower = name.to_lowercase();
        let code_line_lower = code_line.to_lowercase();

        for def in definitions {
            if let Ok(source) = self.parser.get_definition_source(file_path, def) {
                let source_lower = source.to_lowercase();
                let def_name_lower = def.name.to_lowercase();

                trace!(
                    "Checking definition: {} against pattern: {}",
                    def_name_lower,
                    name_lower
                );

                // 名前または行の部分一致を確認
                if def_name_lower.contains(&name_lower) || source_lower.contains(&code_line_lower) {
                    debug!("Found matching general pattern");
                    return Some(CodeDefinition {
                        name: def.name.clone(),
                        context_name_requested: name.to_string(),
                        file_path: file_path.to_path_buf(),
                        source,
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use std::fs;
    use tempfile::tempdir;

    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Trace)
            .try_init();
    }

    #[test]
    fn test_extract_function_definition() -> Result<(), std::io::Error> {
        init();
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.py");

        let content = r#"def test_function(arg1, arg2):
    print("Hello")
    return arg1 + arg2

class TestClass:
    def method(self):
        pass"#;
        fs::write(&file_path, content)?;

        let mut extractor = SymbolExtractor::new(temp_dir.path());
        let files = vec![file_path.clone()];

        // 関数定義の検出をテスト
        let definition = extractor
            .extract("test_function", "def test_function", &files)
            .expect("Failed to extract function definition");

        assert!(definition.source.contains("def test_function"));
        assert!(definition.source.contains("return arg1 + arg2"));

        Ok(())
    }

    #[test]
    fn test_extract_vulnerability_pattern() -> Result<(), std::io::Error> {
        init();
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.py");

        let content = r#"def unsafe_query(user_input):
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
    return cursor.fetchall()

def unsafe_command(cmd):
    os.system(cmd)
    return True

def unsafe_subprocess(user_input):
    subprocess.run(user_input, shell=True)
    subprocess.Popen(f"echo {user_input}", shell=True)
    return True

def xss_vulnerable(request):
    user_input = request.params.get('input')
    template = f"<div>{user_input}</div>"
    return template.render()

def route_handler():
    @app.route('/vulnerable')
    def handle_input():
        user_input = request.form.get('input')
        return eval(user_input)

def unsafe_deserialization(data):
    return pickle.loads(data)"#;
        fs::write(&file_path, content)?;

        let mut extractor = SymbolExtractor::new(temp_dir.path());
        let files = vec![file_path.clone()];

        // SQLインジェクションパターンのテスト
        let sql_def = extractor
            .extract("SQL Injection", "cursor.execute", &files)
            .expect("Failed to extract SQL injection pattern");
        assert!(sql_def.source.contains("cursor.execute"));

        // os.systemを使用したコマンドインジェクションのテスト
        let cmd_def = extractor
            .extract("Command Injection", "os.system", &files)
            .expect("Failed to extract command injection pattern");
        assert!(cmd_def.source.contains("os.system"));

        // subprocess関連のテスト
        let subprocess_def = extractor
            .extract("Command Injection", "subprocess.run", &files)
            .expect("Failed to extract subprocess pattern");
        assert!(subprocess_def.source.contains("subprocess.run"));

        let popen_def = extractor
            .extract("Command Injection", "subprocess.Popen", &files)
            .expect("Failed to extract Popen pattern");
        assert!(popen_def.source.contains("subprocess.Popen"));

        // XSSパターンのテスト
        let xss_def = extractor
            .extract("XSS", "template.render", &files)
            .expect("Failed to extract XSS pattern");
        assert!(xss_def.source.contains("template.render"));

        // ユーザー入力取得のテスト
        let input_def = extractor
            .extract("Input Retrieval", "request.params.get", &files)
            .expect("Failed to extract input retrieval pattern");
        assert!(input_def.source.contains("request.params.get"));

        let form_def = extractor
            .extract("Input Retrieval", "request.form.get", &files)
            .expect("Failed to extract form input pattern");
        assert!(form_def.source.contains("request.form.get"));

        // ルーティングパターンのテスト
        let route_def = extractor
            .extract("Route Definition", "@app.route", &files)
            .expect("Failed to extract route pattern");
        assert!(route_def.source.contains("@app.route"));

        // 一般的なインジェクションパターンのテスト
        let eval_def = extractor
            .extract("Direct Injection", "eval", &files)
            .expect("Failed to extract eval pattern");
        assert!(eval_def.source.contains("eval"));

        let pickle_def = extractor
            .extract("Unsafe Deserialization", "pickle.loads", &files)
            .expect("Failed to extract pickle pattern");
        assert!(pickle_def.source.contains("pickle.loads"));

        Ok(())
    }
}
