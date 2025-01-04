use anyhow::Result;
use anyhow::Result;
use log::{debug, trace};
use stack_graphs::graph::StackGraph;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tree_sitter::Language;
use tree_sitter_stack_graphs::{NoCancellation, StackGraph, StackGraphLanguage};

#[derive(Debug, Clone)]
pub struct Definition {
    pub name: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub source: String,
}

pub struct CodeParser {
    graph: StackGraph,
    files: HashMap<PathBuf, String>,
    languages: HashMap<String, Box<dyn StackGraphLanguage>>,
}

impl CodeParser {
    pub fn new() -> Result<Self> {
        let mut languages = HashMap::new();

        // スクリプト言語
        languages.insert(
            "py".to_string(),
            Box::new(PythonLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "rb".to_string(),
            Box::new(RubyLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "php".to_string(),
            Box::new(PhpLanguage::new()) as Box<dyn StackGraphLanguage>,
        );

        // Webフロントエンド言語
        languages.insert(
            "js".to_string(),
            Box::new(JavaScriptLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "ts".to_string(),
            Box::new(TypeScriptLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "jsx".to_string(),
            Box::new(JavaScriptLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "tsx".to_string(),
            Box::new(TypeScriptLanguage::new()) as Box<dyn StackGraphLanguage>,
        );

        // システムプログラミング言語
        languages.insert(
            "rs".to_string(),
            Box::new(RustLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "go".to_string(),
            Box::new(GoLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "c".to_string(),
            Box::new(CLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "h".to_string(),
            Box::new(CLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "cpp".to_string(),
            Box::new(CppLanguage::new()) as Box<dyn StackGraphLanguage>,
        );
        languages.insert(
            "hpp".to_string(),
            Box::new(CppLanguage::new()) as Box<dyn StackGraphLanguage>,
        );

        // JVM言語
        languages.insert(
            "java".to_string(),
            Box::new(JavaLanguage::new()) as Box<dyn StackGraphLanguage>,
        );

        Ok(Self {
            graph: StackGraph::new(),
            files: HashMap::new(),
            languages,
        })
    }

    pub fn add_file(&mut self, path: &Path) -> Result<()> {
        debug!("Adding file to graph: {}", path.display());
        let content = std::fs::read_to_string(path)?;

        // ファイルをグラフに追加
        let file_id = self
            .graph
            .add_source_file(path.to_string_lossy().as_ref(), &content);
        self.files.insert(path.to_path_buf(), content.clone());

        // 言語に基づいてパースを実行
        if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
            if let Some(language) = self.languages.get(extension) {
                language.parse(&mut self.graph, file_id, &content)?;
            }
        }

        Ok(())
    }

    pub fn find_references(&self, name: &str) -> Vec<(PathBuf, Definition)> {
        let mut results = Vec::new();
        let cancellation = NoCancellation;

        for (path, content) in &self.files {
            if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
                if let Some(language) = self.languages.get(extension) {
                    let file_id = self
                        .graph
                        .source_file(path.to_string_lossy().as_ref())
                        .unwrap();
                    if let Ok(references) =
                        language.find_references(&self.graph, file_id, name, &cancellation)
                    {
                        for reference in references {
                            let start = reference.start;
                            let end = reference.end;
                            results.push((
                                path.clone(),
                                Definition {
                                    name: name.to_string(),
                                    start_byte: start,
                                    end_byte: end,
                                    source: content[start..end].to_string(),
                                },
                            ));
                        }
                    }
                }
            }
        }

        results
    }

    pub fn find_definition(&self, name: &str, source_file: &Path) -> Option<(PathBuf, Definition)> {
        let cancellation = NoCancellation;

        // まず同じファイル内を検索
        if let Some(content) = self.files.get(source_file) {
            if let Some(extension) = source_file.extension().and_then(|e| e.to_str()) {
                if let Some(language) = self.languages.get(extension) {
                    let file_id = self
                        .graph
                        .source_file(source_file.to_string_lossy().as_ref())
                        .unwrap();
                    if let Ok(definitions) =
                        language.find_definitions(&self.graph, file_id, name, &cancellation)
                    {
                        if let Some(definition) = definitions.into_iter().next() {
                            let start = definition.start;
                            let end = definition.end;
                            return Some((
                                source_file.to_path_buf(),
                                Definition {
                                    name: name.to_string(),
                                    start_byte: start,
                                    end_byte: end,
                                    source: content[start..end].to_string(),
                                },
                            ));
                        }
                    }
                }
            }
        }

        // 他のファイルを検索
        for (path, content) in &self.files {
            if path == source_file {
                continue;
            }

            if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
                if let Some(language) = self.languages.get(extension) {
                    let file_id = self
                        .graph
                        .source_file(path.to_string_lossy().as_ref())
                        .unwrap();
                    if let Ok(definitions) =
                        language.find_definitions(&self.graph, file_id, name, &cancellation)
                    {
                        if let Some(definition) = definitions.into_iter().next() {
                            let start = definition.start;
                            let end = definition.end;
                            return Some((
                                path.clone(),
                                Definition {
                                    name: name.to_string(),
                                    start_byte: start,
                                    end_byte: end,
                                    source: content[start..end].to_string(),
                                },
                            ));
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_vulnerability_detection() -> Result<()> {
        let temp_dir = tempdir()?;
        let app_path = temp_dir.path().join("app.py");

        // 脆弱性を含むPythonアプリケーションを作成
        let app_content = r#"
def execute_query(user_data):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE id = " + user_data
    cursor.execute(query)
    return cursor.fetchall()

def process_command(user_input):
    # Command Injection vulnerability
    import os
    os.system("echo " + user_input)
    return True

def render_template(user_data):
    # Template Injection vulnerability
    template = f"<div>{user_data}</div>"
    return template.render()
"#;
        fs::write(&app_path, app_content)?;

        // CodeParserの初期化とファイルの追加
        let mut parser = CodeParser::new()?;
        parser.add_file(&app_path)?;

        // SQL Injection脆弱性の検出をテスト
        let sql_refs = parser.find_references("cursor.execute");
        assert!(
            !sql_refs.is_empty(),
            "Should detect SQL injection vulnerability"
        );

        // Command Injection脆弱性の検出をテスト
        let cmd_refs = parser.find_references("os.system");
        assert!(
            !cmd_refs.is_empty(),
            "Should detect command injection vulnerability"
        );

        // Template Injection脆弱性の検出をテスト
        let template_refs = parser.find_references("template.render");
        assert!(
            !template_refs.is_empty(),
            "Should detect template injection vulnerability"
        );

        Ok(())
    }

    #[test]
    fn test_multiple_language_analysis() -> Result<()> {
        let temp_dir = tempdir()?;

        // 異なる言語で脆弱性を含むファイルを作成
        let python_path = temp_dir.path().join("app.py");
        let js_path = temp_dir.path().join("script.js");
        let cpp_path = temp_dir.path().join("program.cpp");
        let php_path = temp_dir.path().join("index.php");

        // Pythonファイル
        let python_content = r#"
def render_template(user_input):
    template = f"<div>{user_input}</div>"
    return template.render()
"#;
        fs::write(&python_path, python_content)?;

        // JavaScriptファイル
        let js_content = r#"
function processUserInput(input) {
    // XSS vulnerability
    document.innerHTML = input;
    
    // Eval vulnerability
    eval(input);
}
"#;
        fs::write(&js_path, js_content)?;

        // C++ファイル
        let cpp_content = r#"
void processCommand(const std::string& input) {
    // Command injection vulnerability
    system(input.c_str());
}
"#;
        fs::write(&cpp_path, cpp_content)?;

        // PHPファイル
        let php_content = r#"
<?php
function process_data($user_input) {
    // SQL Injection vulnerability
    $query = "SELECT * FROM users WHERE id = " . $user_input;
    mysql_query($query);
}
?>"#;
        fs::write(&php_path, php_content)?;

        // CodeParserの初期化とファイルの追加
        let mut parser = CodeParser::new()?;
        parser.add_file(&python_path)?;
        parser.add_file(&js_path)?;
        parser.add_file(&cpp_path)?;
        parser.add_file(&php_path)?;

        // 各言語の脆弱性検出をテスト
        let template_refs = parser.find_references("render");
        assert!(
            !template_refs.is_empty(),
            "Should detect template injection in Python"
        );

        let eval_refs = parser.find_references("eval");
        assert!(
            !eval_refs.is_empty(),
            "Should detect eval vulnerability in JavaScript"
        );

        let system_refs = parser.find_references("system");
        assert!(
            !system_refs.is_empty(),
            "Should detect command injection in C++"
        );

        let mysql_refs = parser.find_references("mysql_query");
        assert!(!mysql_refs.is_empty(), "Should detect SQL injection in PHP");

        Ok(())
    }

    #[test]
    fn test_complex_dependency_chain() -> Result<()> {
        let temp_dir = tempdir()?;

        // 複雑な依存関係を持つファイルを作成
        let config_path = temp_dir.path().join("config.rb");
        let db_path = temp_dir.path().join("database.rb");
        let service_path = temp_dir.path().join("service.rb");
        let api_path = temp_dir.path().join("api.rb");

        // 設定ファイル (Ruby)
        let config_content = r#"
def get_database_config
  {
    host: 'localhost',
    user: 'admin'
  }
end"#;
        fs::write(&config_path, config_content)?;

        // データベース層
        let db_content = r#"
require_relative 'config'

def execute_query(query)
  config = get_database_config
  # SQL Injection vulnerability
  ActiveRecord::Base.connection.execute(query)
end"#;
        fs::write(&db_path, db_content)?;

        // サービス層
        let service_content = r#"
require_relative 'database'

def process_user_data(user_input)
  query = "SELECT * FROM users WHERE id = #{user_input}"
  execute_query(query)
end"#;
        fs::write(&service_path, service_content)?;

        // API層
        let api_content = r#"
require_relative 'service'

def handle_request(request)
  user_id = request.params['id']
  process_user_data(user_id)
end"#;
        fs::write(&api_path, api_content)?;

        // CodeParserの初期化とファイルの追加
        let mut parser = CodeParser::new()?;
        parser.add_file(&config_path)?;
        parser.add_file(&db_path)?;
        parser.add_file(&service_path)?;
        parser.add_file(&api_path)?;

        // 依存関係チェーンを通じた脆弱性の検出をテスト
        let query_refs = parser.find_references("execute_query");
        assert!(
            query_refs.len() >= 2,
            "Should find all references to execute_query"
        );

        // 設定の依存関係をテスト
        let config_refs = parser.find_references("get_database_config");
        assert!(
            config_refs.len() >= 2,
            "Should find all references to database config"
        );

        Ok(())
    }
}
