use stack_graphs::graph::StackGraph;
use stack_graphs::storage::SQLiteWriter;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use tree_sitter_stack_graphs::loader::LanguageConfiguration;
use tree_sitter_stack_graphs::NoCancellation;

#[derive(Debug, Clone)]
pub struct StackGraphsError {
    message: String,
}

impl StackGraphsError {
    pub fn from(message: String) -> StackGraphsError {
        StackGraphsError { message }
    }
}

impl fmt::Display for StackGraphsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for StackGraphsError {}

#[derive(Debug, Clone)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
    Java,
}

pub fn get_langauge_configuration(lang: &Language) -> LanguageConfiguration {
    match lang {
        Language::Python => {
            tree_sitter_stack_graphs_python::language_configuration(&NoCancellation)
        }
        Language::JavaScript => {
            tree_sitter_stack_graphs_javascript::language_configuration(&NoCancellation)
        }
        Language::TypeScript => {
            tree_sitter_stack_graphs_typescript::language_configuration_typescript(&NoCancellation)
        }
        Language::Java => tree_sitter_stack_graphs_java::language_configuration(&NoCancellation),
    }
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
    languages: HashMap<String, LanguageConfiguration>,
}

impl CodeParser {
    pub fn new(db_path: Option<&str>) -> Result<Self, StackGraphsError> {
        let mut languages = HashMap::new();

        // Add supported languages
        languages.insert(
            "py".to_string(),
            get_langauge_configuration(&Language::Python),
        );
        languages.insert(
            "js".to_string(),
            get_langauge_configuration(&Language::JavaScript),
        );
        languages.insert(
            "ts".to_string(),
            get_langauge_configuration(&Language::TypeScript),
        );
        languages.insert(
            "java".to_string(),
            get_langauge_configuration(&Language::Java),
        );

        let db_writer = if let Some(path) = db_path {
            SQLiteWriter::open(path)
                .map_err(|e| StackGraphsError::from(format!("Failed to open database: {}", e)))?
        } else {
            SQLiteWriter::open_in_memory().map_err(|e| {
                StackGraphsError::from(format!("Failed to create in-memory database: {}", e))
            })?
        };

        Ok(Self {
            graph: StackGraph::new(),
            db_writer,
            files: HashMap::new(),
            languages,
        })
    }

    pub fn add_file(&mut self, path: &Path) -> Result<(), StackGraphsError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| StackGraphsError::from(format!("Failed to read file: {}", e)))?;

        // Add file to graph
        let file_path = path.to_string_lossy().to_string();
        let file_id = self.graph.add_file(&file_path);
        self.files.insert(path.to_path_buf(), content.clone());

        Ok(())
    }

    pub fn find_references(&self, name: &str) -> Vec<(PathBuf, Definition)> {
        let mut results = Vec::new();

        // TODO

        results
    }

    pub fn find_definition(&self, name: &str, source_file: &Path) -> Option<(PathBuf, Definition)> {
        // TODO

        None
    }
}
