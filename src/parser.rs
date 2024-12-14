use anyhow::Result;
use std::path::Path;
use tree_sitter::{Language, Parser, Query, QueryCursor};

extern "C" {
    fn tree_sitter_python() -> Language;
    fn tree_sitter_javascript() -> Language;
    fn tree_sitter_typescript() -> Language;
    fn tree_sitter_rust() -> Language;
    fn tree_sitter_go() -> Language;
    fn tree_sitter_java() -> Language;
}

#[derive(Debug)]
pub struct Definition {
    pub name: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

pub struct CodeParser {
    parser: Parser,
    languages: Vec<(Language, &'static str, &'static str)>,
}

impl CodeParser {
    pub fn new() -> Result<Self> {
        let parser = Parser::new();

        // Initialize supported languages with their queries
        let languages = vec![
            unsafe { (tree_sitter_python(), "python", "(function_definition name: (identifier) @name) (class_definition name: (identifier) @name)") },
            unsafe { (tree_sitter_javascript(), "javascript", "(function_declaration name: (identifier) @name) (class_declaration name: (identifier) @name)") },
            unsafe { (tree_sitter_typescript(), "typescript", "(function_declaration name: (identifier) @name) (class_declaration name: (identifier) @name)") },
            unsafe { (tree_sitter_rust(), "rust", "(function_item name: (identifier) @name) (struct_item name: (type_identifier) @name)") },
            unsafe { (tree_sitter_go(), "go", "(function_declaration name: (identifier) @name) (type_declaration (type_spec name: (type_identifier) @name))") },
            unsafe { (tree_sitter_java(), "java", "(method_declaration name: (identifier) @name) (class_declaration name: (identifier) @name)") },
        ];

        Ok(Self { parser, languages })
    }

    pub fn parse_file(&mut self, path: &Path) -> Result<Vec<Definition>> {
        let content = std::fs::read_to_string(path)?;
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        // Find the appropriate language based on file extension
        let language = match extension {
            "py" => &self.languages[0],
            "js" => &self.languages[1],
            "ts" => &self.languages[2],
            "rs" => &self.languages[3],
            "go" => &self.languages[4],
            "java" => &self.languages[5],
            _ => return Ok(vec![]), // Unsupported file type
        };

        self.parser.set_language(language.0)?;
        let tree = self.parser.parse(&content, None).ok_or_else(|| {
            anyhow::anyhow!("Failed to parse file: {}", path.display())
        })?;

        let query = Query::new(language.0, language.2)?;
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), content.as_bytes());

        let mut definitions = Vec::new();
        for match_ in matches {
            for capture in match_.captures {
                let name = capture.node.utf8_text(content.as_bytes())?.to_string();
                definitions.push(Definition {
                    name,
                    start_byte: capture.node.start_byte(),
                    end_byte: capture.node.end_byte(),
                });
            }
        }

        Ok(definitions)
    }

    pub fn get_definition_source(&self, path: &Path, def: &Definition) -> Result<String> {
        let content = std::fs::read_to_string(path)?;
        Ok(content[def.start_byte..def.end_byte].to_string())
    }
}
