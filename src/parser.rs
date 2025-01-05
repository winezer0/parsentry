use stack_graphs::graph::StackGraph;
use stack_graphs::storage::SQLiteWriter;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use tree_sitter_stack_graphs::{
    cli::index::IndexArgs,
    loader::{LanguageConfiguration, Loader},
    NoCancellation, StackGraphLanguage, Variables,
};

#[derive(Debug, Clone)]
pub struct StackGraphsError {
    message: String,
}

impl fmt::Display for StackGraphsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for StackGraphsError {}

pub fn get_language_configurations(language: &str) -> Vec<LanguageConfiguration> {
    match language.to_lowercase().as_str() {
        "python" => vec![tree_sitter_stack_graphs_python::language_configuration(
            &NoCancellation,
        )],
        "javascript" => vec![tree_sitter_stack_graphs_javascript::language_configuration(
            &NoCancellation,
        )],
        "typescript" => vec![
            tree_sitter_stack_graphs_typescript::language_configuration_typescript(&NoCancellation),
        ],
        "java" => vec![tree_sitter_stack_graphs_java::language_configuration(
            &NoCancellation,
        )],
        _ => vec![],
    }
}

pub fn index_files(files: Vec<PathBuf>, language: &str) -> Result<(), anyhow::Error> {
    let language_configurations = get_language_configurations(language);

    let index_args = IndexArgs {
        source_paths: files,
        continue_from: None,
        verbose: true,
        hide_error_details: false,
        max_file_time: None,
        wait_at_start: false,
        stats: true,
        force: true,
    };

    let directory = std::env::current_dir()?;
    let default_db_path = directory
        .join(format!("{}.sqlite", env!("CARGO_PKG_NAME")))
        .to_path_buf();

    let loader = Loader::from_language_configurations(language_configurations, None)
        .expect("Expected loader");

    log::info!(
        "Starting graph indexing inside {} \n",
        default_db_path.display()
    );

    index_args.run(&default_db_path, loader)
}

#[derive(Debug, Clone)]
pub struct Definition {
    pub name: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub source: String,
}

pub struct CodeParser {
    graph: StackGraph,
    db_writer: SQLiteWriter,
    files: HashMap<PathBuf, String>,
    python_config: LanguageConfiguration,
    javascript_config: LanguageConfiguration,
    typescript_config: LanguageConfiguration,
    java_config: LanguageConfiguration,
}

impl CodeParser {
    pub fn new(db_path: Option<&str>) -> Result<Self, StackGraphsError> {
        let mut python_configs = get_language_configurations("python");
        let mut javascript_configs = get_language_configurations("javascript");
        let mut typescript_configs = get_language_configurations("typescript");
        let mut java_configs = get_language_configurations("java");

        let db_writer = if let Some(path) = db_path {
            SQLiteWriter::open(path).map_err(|e| StackGraphsError {
                message: format!("Failed to open database: {}", e),
            })?
        } else {
            SQLiteWriter::open_in_memory().map_err(|e| StackGraphsError {
                message: format!("Failed to create in-memory database: {}", e),
            })?
        };

        Ok(Self {
            graph: StackGraph::new(),
            db_writer,
            files: HashMap::new(),
            python_config: python_configs.remove(0),
            javascript_config: javascript_configs.remove(0),
            typescript_config: typescript_configs.remove(0),
            java_config: java_configs.remove(0),
        })
    }

    pub fn add_file(&mut self, path: &Path) -> Result<(), StackGraphsError> {
        let content = std::fs::read_to_string(path).map_err(|e| StackGraphsError {
            message: format!("Failed to read file: {}", e),
        })?;

        // Add file to graph
        let file_path = path.to_string_lossy().to_string();
        let file_id = self.graph.get_or_create_file(&file_path);
        self.files.insert(path.to_path_buf(), content.clone());

        // Get file extension to determine language
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();

        let language = match ext.as_str() {
            "py" => Some(&self.python_config),
            "js" => Some(&self.javascript_config),
            "ts" => Some(&self.typescript_config),
            "java" => Some(&self.java_config),
            _ => None,
        };

        if let Some(language) = language {
            let globals = Variables::new();
            // Parse and add to graph immediately
            language
                .sgl
                .build_stack_graph_into(
                    &mut self.graph,
                    file_id,
                    &content,
                    &globals,
                    &NoCancellation,
                )
                .map_err(|e| StackGraphsError {
                    message: format!("Failed to build stack graph: {}", e),
                })?;
        }

        Ok(())
    }

    pub fn find_references(&self, name: &str) -> Vec<(PathBuf, Definition)> {
        let mut results = Vec::new();
        let mut seen_positions = std::collections::HashSet::new();

        for (file_path, content) in &self.files {
            let mut line_number = 0;
            let mut in_import = false;

            for line in content.lines() {
                let line_start =
                    content[..content.lines().take(line_number).collect::<String>().len()].len()
                        + if line_number > 0 { 1 } else { 0 };

                let line_trimmed = line.trim_start();
                if line_trimmed.starts_with("from ") || line_trimmed.starts_with("import ") {
                    in_import = true;
                } else if line_trimmed.is_empty() {
                    in_import = false;
                }

                if line_trimmed.starts_with("def ") || line_trimmed.starts_with("function ") {
                    line_number += 1;
                    continue;
                }

                if in_import {
                    line_number += 1;
                    continue;
                }

                if let Some(pos) = line.find(name) {
                    let before_name = &line[..pos];
                    let is_reference = before_name.ends_with(" = ")
                        || before_name.ends_with("(")
                        || before_name.ends_with(" ")
                        || before_name.is_empty();

                    if is_reference {
                        let start_byte = line_start + pos;
                        let end_byte = start_byte + name.len();

                        let position = (file_path.clone(), start_byte, end_byte);
                        if !seen_positions.contains(&position) {
                            seen_positions.insert(position.clone());
                            results.push((
                                file_path.clone(),
                                Definition {
                                    name: name.to_string(),
                                    start_byte,
                                    end_byte,
                                    source: name.to_string(),
                                },
                            ));
                        }
                    }
                }

                line_number += 1;
            }
        }

        results
    }

    pub fn find_definition(
        &mut self,
        name: &str,
        source_file: &Path,
    ) -> Result<Option<(PathBuf, Definition)>, StackGraphsError> {
        use stack_graphs::graph::Node;

        // Get file content
        let content = self
            .files
            .get(source_file)
            .ok_or_else(|| StackGraphsError {
                message: "File not found in parser".to_string(),
            })?;

        Ok(self.graph.iter_nodes().find_map(|handle| {
            let node = &self.graph[handle];
            if !node.is_definition() {
                return None;
            }

            if let Some(symbol) = node.symbol() {
                let symbol_name = &self.graph[symbol];
                if symbol_name == name {
                    if let Some(source_info) = self.graph.source_info(handle) {
                        let source = content[source_info.span.start.column.utf8_offset
                            ..source_info.span.end.column.utf8_offset]
                            .to_string();

                        return Some((
                            source_file.to_path_buf(),
                            Definition {
                                name: name.to_string(),
                                start_byte: source_info.span.start.column.utf8_offset,
                                end_byte: source_info.span.end.column.utf8_offset,
                                source,
                            },
                        ));
                    }
                }
            }
            None
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_find_definition() -> Result<(), StackGraphsError> {
        let mut parser = CodeParser::new(None)?;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.py");
        std::fs::write(&file_path, "def test_function():\n    pass\n").unwrap();

        parser.add_file(&file_path)?;

        let result = parser.find_definition("test_function", &file_path)?;
        assert!(result.is_some());

        let (path, def) = result.unwrap();
        assert_eq!(path, file_path);
        assert_eq!(def.name, "test_function");
        assert_eq!(def.source, "test_function");

        let result = parser.find_definition("non_existent", &file_path)?;
        assert!(result.is_none());

        Ok(())
    }

    #[test]
    fn test_find_references() -> Result<(), StackGraphsError> {
        let mut parser = CodeParser::new(None)?;
        let temp_dir = tempfile::tempdir().unwrap();

        let file_path1 = temp_dir.path().join("main.py");
        std::fs::write(
            &file_path1,
            r#"def test_function():
    return "Hello"

x = test_function

if True:
    y = test_function"#,
        )
        .unwrap();

        let file_path2 = temp_dir.path().join("test.py");
        std::fs::write(
            &file_path2,
            r#"from main import test_function

def another_function():
    z = test_function"#,
        )
        .unwrap();

        parser.add_file(&file_path1)?;
        parser.add_file(&file_path2)?;

        let references = parser.find_references("test_function");
        assert_eq!(references.len(), 3, "Expected exactly 3 references");

        let main_refs: Vec<_> = references
            .iter()
            .filter(|(path, _)| path == &file_path1)
            .collect();
        let test_refs: Vec<_> = references
            .iter()
            .filter(|(path, _)| path == &file_path2)
            .collect();

        assert_eq!(main_refs.len(), 2, "Expected 2 references in main.py");
        assert_eq!(test_refs.len(), 1, "Expected 1 reference in test.py");

        for (_, def) in references {
            assert_eq!(def.name, "test_function");
            assert_eq!(def.source, "test_function");
        }

        let references = parser.find_references("non_existent");
        assert!(references.is_empty());

        let js_file = temp_dir.path().join("test.js");
        std::fs::write(
            &js_file,
            r#"function testFunction() {
    return true;
}

let x = testFunction();

if (true) {
    let y = testFunction();
}"#,
        )
        .unwrap();

        parser.add_file(&js_file)?;
        let references = parser.find_references("testFunction");
        assert_eq!(
            references.len(),
            2,
            "Expected exactly 2 references in JS file"
        );

        for (path, def) in references {
            assert_eq!(path, js_file);
            assert_eq!(def.name, "testFunction");
            assert_eq!(def.source, "testFunction");
        }

        Ok(())
    }

    #[test]
    fn test_index_files() -> Result<(), anyhow::Error> {
        let temp_dir = TempDir::new()?;
        let python_file = temp_dir.path().join("test.py");
        let js_file = temp_dir.path().join("test.js");

        std::fs::write(&python_file, "def test_function():\n    pass\n")?;
        std::fs::write(&js_file, "function testFunction() {\n    return true;\n}")?;

        let result = index_files(vec![python_file.clone()], "python");
        assert!(result.is_ok());

        let result = index_files(vec![js_file.clone()], "javascript");
        assert!(result.is_ok());

        let result = index_files(vec![python_file], "invalid");
        assert!(result.is_ok());

        Ok(())
    }
}
