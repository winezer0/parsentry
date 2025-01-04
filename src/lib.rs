pub mod analyzer;
pub mod parser;
pub mod prompts;
pub mod repo;
pub mod response;
pub mod security_patterns;

#[cfg(test)]
mod tests {
    use crate::parser::CodeParser;
    use anyhow::Result;
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
        let java_path = temp_dir.path().join("Service.java");

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

        // Javaファイル
        let java_content = r#"
public class Service {
    public void processCommand(String input) {
        // Command injection vulnerability
        Runtime.getRuntime().exec(input);
    }
}
"#;
        fs::write(&java_path, java_content)?;

        // CodeParserの初期化とファイルの追加
        let mut parser = CodeParser::new()?;
        parser.add_file(&python_path)?;
        parser.add_file(&js_path)?;
        parser.add_file(&java_path)?;

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

        let exec_refs = parser.find_references("exec");
        assert!(
            !exec_refs.is_empty(),
            "Should detect command injection in Java"
        );

        Ok(())
    }

    #[test]
    fn test_complex_dependency_chain() -> Result<()> {
        let temp_dir = tempdir()?;

        // 複雑な依存関係を持つファイルを作成
        let config_path = temp_dir.path().join("config.py");
        let db_path = temp_dir.path().join("database.py");
        let service_path = temp_dir.path().join("service.py");
        let api_path = temp_dir.path().join("api.py");

        // 設定ファイル
        let config_content = r#"
def get_database_config():
    return {
        'host': 'localhost',
        'user': 'admin'
    }
"#;
        fs::write(&config_path, config_content)?;

        // データベース層
        let db_content = r#"
from config import get_database_config

def execute_query(query):
    config = get_database_config()
    # SQL Injection vulnerability
    return cursor.execute(query)
"#;
        fs::write(&db_path, db_content)?;

        // サービス層
        let service_content = r#"
from database import execute_query

def process_user_data(user_input):
    query = "SELECT * FROM users WHERE id = " + user_input
    return execute_query(query)
"#;
        fs::write(&service_path, service_content)?;

        // API層
        let api_content = r#"
from service import process_user_data

def handle_request(request):
    user_id = request.get('id')
    return process_user_data(user_id)
"#;
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
