use std::path::{Path, PathBuf};

use crate::parser::{CodeParser, Definition};

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
        for file_path in files {
            // Try to parse the file and find definitions
            if let Ok(definitions) = self.parser.parse_file(file_path) {
                // First try to find exact match for the code line
                if let Some(definition) =
                    self.find_definition_by_line(&definitions, name, code_line, file_path)
                {
                    return Some(definition);
                }

                // If no exact match, try to find by name
                if let Some(definition) =
                    self.find_definition_by_name(&definitions, name, file_path)
                {
                    return Some(definition);
                }
            }
        }
        None
    }

    fn find_definition_by_line(
        &self,
        definitions: &[Definition],
        name: &str,
        code_line: &str,
        file_path: &Path,
    ) -> Option<CodeDefinition> {
        for def in definitions {
            if let Ok(source) = self.parser.get_definition_source(file_path, def) {
                if source.contains(code_line) {
                    return Some(CodeDefinition {
                        name: name.to_string(),
                        context_name_requested: name.to_string(),
                        file_path: file_path.to_path_buf(),
                        source,
                    });
                }
            }
        }
        None
    }

    fn find_definition_by_name(
        &self,
        definitions: &[Definition],
        name: &str,
        file_path: &Path,
    ) -> Option<CodeDefinition> {
        for def in definitions {
            if def.name == name {
                if let Ok(source) = self.parser.get_definition_source(file_path, def) {
                    return Some(CodeDefinition {
                        name: name.to_string(),
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
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_extract_function_definition() -> Result<(), std::io::Error> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.py");

        let content = r#"
def test_function(arg1, arg2):
    print("Hello")
    return arg1 + arg2

class TestClass:
    def method(self):
        pass
"#;
        fs::write(&file_path, content)?;

        let mut extractor = SymbolExtractor::new(temp_dir.path());
        let files = vec![file_path.clone()];

        let definition = extractor
            .extract("test_function", "def test_function(arg1, arg2):", &files)
            .unwrap();

        assert_eq!(definition.name, "test_function");
        assert!(definition.source.contains("def test_function"));
        assert!(definition.source.contains("return arg1 + arg2"));

        Ok(())
    }

    #[test]
    fn test_extract_class_definition() -> Result<(), std::io::Error> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.py");

        let content = r#"
class TestClass:
    def method(self):
        print("Hello")
        return True
"#;
        fs::write(&file_path, content)?;

        let mut extractor = SymbolExtractor::new(temp_dir.path());
        let files = vec![file_path.clone()];

        let definition = extractor
            .extract("TestClass", "class TestClass:", &files)
            .unwrap();

        assert_eq!(definition.name, "TestClass");
        assert!(definition.source.contains("class TestClass"));
        assert!(definition.source.contains("def method"));

        Ok(())
    }
}
