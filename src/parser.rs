use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use anyhow::{anyhow, Result};
use tree_sitter::{Language, Parser, Query, QueryCursor, Node};
use streaming_iterator::StreamingIterator; // Import the trait

// Import language functions from tree-sitter crates
extern "C" {
    fn tree_sitter_python() -> Language;
    fn tree_sitter_javascript() -> Language;
    fn tree_sitter_typescript() -> Language;
    fn tree_sitter_tsx() -> Language;
    fn tree_sitter_java() -> Language;
    // Add other languages here if needed
}

#[derive(Debug, Clone)]
pub struct Definition {
    pub name: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub source: String,
}

pub struct CodeParser {
    files: HashMap<PathBuf, String>,
    parser: Parser,
}

impl CodeParser {
    pub fn new() -> Result<Self> {
        Ok(Self {
            files: HashMap::new(),
            parser: Parser::new(),
        })
    }

    pub fn add_file(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read file {}: {}", path.display(), e))?;
        self.files.insert(path.to_path_buf(), content.clone());
        Ok(())
    }

    // Helper function to get tree-sitter language from path
    fn get_language(&self, path: &Path) -> Option<Language> {
        let extension = path.extension().and_then(|ext| ext.to_str());
        match extension {
            Some("py") => Some(unsafe { tree_sitter_python() }),
            Some("js") => Some(unsafe { tree_sitter_javascript() }),
            Some("ts") => Some(unsafe { tree_sitter_typescript() }),
            Some("tsx") => Some(unsafe { tree_sitter_tsx() }),
            Some("java") => Some(unsafe { tree_sitter_java() }),
            // Add other extensions here
            _ => None,
        }
    }

    // Helper function to get the path to the query file
    fn get_query_path(&self, language: &Language, query_name: &str) -> Result<PathBuf> {
        let lang_name = if language == &unsafe { tree_sitter_python() } {
            "python"
        } else if language == &unsafe { tree_sitter_javascript() } {
            "javascript"
        } else if language == &unsafe { tree_sitter_typescript() } || language == &unsafe { tree_sitter_tsx() } {
            // Use "typescript" subdir for both TS and TSX custom queries
            "typescript"
        } else if language == &unsafe { tree_sitter_java() } {
            "java"
        } else {
            return Err(anyhow!("Unsupported language for queries"));
        };

        // Construct the path relative to the Cargo manifest directory, pointing to custom_queries
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let query_path = manifest_dir
            .join("custom_queries") // Point to the new custom_queries directory
            .join(lang_name)        // Use the language name subdirectory
            .join(format!("{}.scm", query_name));

        if !query_path.exists() {
            return Err(anyhow!("Query file not found: {}", query_path.display()));
        }

        Ok(query_path)
    }

    pub fn find_definition(
        &mut self,
        name: &str,
        source_file: &Path,
    ) -> Result<Option<(PathBuf, Definition)>> {
        let content = self
            .files
            .get(source_file)
            .ok_or_else(|| anyhow!("File not found in parser: {}", source_file.display()))?;

        let language = match self.get_language(source_file) {
            Some(lang) => lang,
            None => return Ok(None),
        };

        self.parser
            .set_language(&language)
            .map_err(|e| anyhow!("Failed to set language: {}", e))?;

        let tree = self
            .parser
            .parse(content, None)
            .ok_or_else(|| anyhow!("Failed to parse file: {}", source_file.display()))?;

        // Pass language by reference to get_query_path
        let query_path = self.get_query_path(&language, "definitions")?;
        let query_str = fs::read_to_string(&query_path)
            .map_err(|e| anyhow!("Failed to read query file {}: {}", query_path.display(), e))?;

        let query = Query::new(&language, &query_str)
            .map_err(|e| anyhow!("Failed to create query from {}: {}", query_path.display(), e))?;

        let mut query_cursor = QueryCursor::new();
        let mut matches = query_cursor.matches(&query, tree.root_node(), content.as_bytes());

        while let Some(mat) = matches.next() {
            let mut definition_node: Option<Node> = None;
            let mut name_node: Option<Node> = None;

            for cap in mat.captures {
                let capture_name = &query.capture_names()[cap.index as usize];
                // Dereference s for comparison with &str
                match capture_name {
                    s if *s == "definition" => definition_node = Some(cap.node),
                    s if *s == "name" => name_node = Some(cap.node),
                    _ => {}
                }
            }

            if let (Some(def_node), Some(name_node_inner)) = (definition_node, name_node) {
                if name_node_inner.utf8_text(content.as_bytes())? == name {
                    let start_byte = def_node.start_byte();
                    let end_byte = def_node.end_byte();
                    let source = def_node.utf8_text(content.as_bytes())?.to_string();

                    let definition = Definition {
                        name: name.to_string(),
                        start_byte,
                        end_byte,
                        source,
                    };
                    return Ok(Some((source_file.to_path_buf(), definition)));
                }
            }
        }

        Ok(None)
    }

    pub fn find_references(&mut self, name: &str) -> Result<Vec<(PathBuf, Definition)>> {
        let mut results = Vec::new();

        for (file_path, content) in &self.files {
            let language = match self.get_language(file_path) {
                Some(lang) => lang,
                None => continue,
            };

            self.parser
                .set_language(&language)
                .map_err(|e| anyhow!("Failed to set language for {}: {}", file_path.display(), e))?;

            let tree = match self.parser.parse(content, None) {
                Some(t) => t,
                None => {
                    eprintln!("Warning: Failed to parse file: {}", file_path.display());
                    continue;
                }
            };

            // Pass language by reference to get_query_path
            let query_path = match self.get_query_path(&language, "references") {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to get references query path for {}: {}",
                        file_path.display(),
                        e
                    );
                    continue;
                }
            };
            let query_str = match fs::read_to_string(&query_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to read references query file {}: {}",
                        query_path.display(),
                        e
                    );
                    continue;
                }
            };

            let query = match Query::new(&language, &query_str) {
                Ok(q) => q,
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to create references query from {}: {}",
                        query_path.display(),
                        e
                    );
                    continue;
                }
            };

            let mut query_cursor = QueryCursor::new();
            let mut matches = query_cursor.matches(&query, tree.root_node(), content.as_bytes());

            while let Some(mat) = matches.next() {
                for cap in mat.captures {
                    // Remove the extra & for comparison
                    if query.capture_names()[cap.index as usize] == "reference" {
                        let node = cap.node;
                        if node.utf8_text(content.as_bytes())? == name {
                            let start_byte = node.start_byte();
                            let end_byte = node.end_byte();
                            let source = name.to_string();

                            results.push((
                                file_path.clone(),
                                Definition {
                                    name: name.to_string(),
                                    start_byte,
                                    end_byte,
                                    source,
                                },
                            ));
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs; // Keep fs import needed for test_find_references

    #[test]
    fn test_find_definition() -> Result<()> {
        let mut parser = CodeParser::new()?;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.py");
        let file_content = "def test_function():\n    pass\n";
        std::fs::write(&file_path, file_content).unwrap();

        parser.add_file(&file_path)?;

        let result = parser.find_definition("test_function", &file_path)?;
        assert!(result.is_some(), "Definition should be found");

        let (path, def) = result.unwrap();
        assert_eq!(path, file_path);
        assert_eq!(def.name, "test_function");
        assert_eq!(def.source, "def test_function():\n    pass");
        assert_eq!(def.start_byte, 0);
        assert_eq!(def.end_byte, 29, "End byte should match the node span");

        let result = parser.find_definition("non_existent", &file_path)?;
        assert!(result.is_none(), "Non-existent definition should not be found");

        Ok(())
    }

    #[test]
    fn test_find_references() -> Result<()> {
        let mut parser = CodeParser::new()?;
        let temp_dir = tempfile::tempdir().unwrap();

        let file_path1 = temp_dir.path().join("main.py");
        let content1 = r#"def test_function():
    return "Hello"

x = test_function()

if True:
    y = test_function()"#;
        std::fs::write(&file_path1, content1).unwrap();

        let file_path2 = temp_dir.path().join("test.py");
        let content2 = r#"from main import test_function

def another_function():
    z = test_function()"#;
        std::fs::write(&file_path2, content2).unwrap();

        parser.add_file(&file_path1)?;
        parser.add_file(&file_path2)?;

        let references = parser.find_references("test_function")?;
        
        assert_eq!(references.len(), 5, "Expected 5 references (including definition and import)");

        let main_refs_count = references.iter().filter(|(p, _)| p == &file_path1).count();
        let test_refs_count = references.iter().filter(|(p, _)| p == &file_path2).count();

        assert_eq!(main_refs_count, 3, "Expected 3 references in main.py");
        assert_eq!(test_refs_count, 2, "Expected 2 references in test.py");

        for (path, def) in references {
            assert_eq!(def.name, "test_function");
            assert_eq!(def.source, "test_function");
            let file_content = fs::read_to_string(path)?;
            assert_eq!(&file_content[def.start_byte..def.end_byte], "test_function");
        }

        let references_non_existent = parser.find_references("non_existent")?;
        assert!(references_non_existent.is_empty(), "Should find no references for non-existent name");

        Ok(())
    }
}
