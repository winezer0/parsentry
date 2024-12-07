use anyhow::{anyhow, Result};
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};

pub struct CodeParser {
    parser: Parser,
}

#[derive(Debug)]
pub struct Definition {
    pub name: String,
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

impl CodeParser {
    pub fn new() -> Result<Self> {
        let parser = Parser::new();
        Ok(Self { parser })
    }

    pub fn parse_file(&mut self, file_path: &Path) -> Result<Vec<Definition>> {
        let content = std::fs::read_to_string(file_path)?;
        let extension = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .ok_or_else(|| anyhow!("File has no extension"))?;

        let (language, query_source) = match extension {
            "py" => (
                tree_sitter_python::language(),
                r#"
                (function_definition
                    name: (identifier) @function.name) @function.def
                (class_definition
                    name: (identifier) @class.name) @class.def
                "#,
            ),
            "js" | "jsx" => (
                tree_sitter_javascript::language(),
                r#"
                (function_declaration
                    name: (identifier) @function.name) @function.def
                (class_declaration
                    name: (identifier) @class.name) @class.def
                (method_definition
                    name: (property_identifier) @method.name) @method.def
                "#,
            ),
            "ts" | "tsx" => (
                // TypeScript uses the same parser as JavaScript
                tree_sitter_javascript::language(),
                r#"
                (function_declaration
                    name: (identifier) @function.name) @function.def
                (class_declaration
                    name: (type_identifier) @class.name) @class.def
                (method_definition
                    name: (property_identifier) @method.name) @method.def
                "#,
            ),
            "rs" => (
                tree_sitter_rust::language(),
                r#"
                (function_item
                    name: (identifier) @function.name) @function.def
                (struct_item
                    name: (type_identifier) @struct.name) @struct.def
                (impl_item
                    trait: (type_identifier)? @trait.name
                    type: (type_identifier) @type.name) @impl.def
                "#,
            ),
            "go" => (
                tree_sitter_go::language(),
                r#"
                (function_declaration
                    name: (identifier) @function.name) @function.def
                (method_declaration
                    name: (field_identifier) @method.name) @method.def
                (type_declaration
                    (type_spec
                        name: (type_identifier) @type.name)) @type.def
                "#,
            ),
            "java" => (
                tree_sitter_java::language(),
                r#"
                (method_declaration
                    name: (identifier) @method.name) @method.def
                (class_declaration
                    name: (identifier) @class.name) @class.def
                (interface_declaration
                    name: (identifier) @interface.name) @interface.def
                "#,
            ),
            _ => return Err(anyhow!("Unsupported file type: {}", extension)),
        };

        self.parser.set_language(language)?;
        let tree = self
            .parser
            .parse(&content, None)
            .ok_or_else(|| anyhow!("Failed to parse file: {}", file_path.display()))?;

        let query = Query::new(language, query_source)?;
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), content.as_bytes());

        let mut definitions = Vec::new();
        for match_ in matches {
            for capture in match_.captures {
                let capture_name = query.capture_names()[capture.index as usize].as_str();
                if capture_name.ends_with(".name") {
                    let node = capture.node;
                    let name = node.utf8_text(content.as_bytes())?.to_string();
                    let kind = capture_name
                        .split('.')
                        .next()
                        .unwrap_or("unknown")
                        .to_string();

                    // Find the definition node (parent of the name node)
                    let def_node = node
                        .parent()
                        .ok_or_else(|| anyhow!("Failed to get parent node for: {}", name))?;

                    definitions.push(Definition {
                        name,
                        kind,
                        start_byte: def_node.start_byte(),
                        end_byte: def_node.end_byte(),
                    });
                }
            }
        }

        Ok(definitions)
    }

    pub fn get_definition_source(&self, file_path: &Path, def: &Definition) -> Result<String> {
        let content = std::fs::read_to_string(file_path)?;
        Ok(content[def.start_byte..def.end_byte].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_parse_python() -> Result<()> {
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

        let mut parser = CodeParser::new()?;
        let definitions = parser.parse_file(&file_path)?;

        assert_eq!(definitions.len(), 3);
        assert!(definitions.iter().any(|d| d.name == "test_function"));
        assert!(definitions.iter().any(|d| d.name == "TestClass"));
        assert!(definitions.iter().any(|d| d.name == "method"));

        Ok(())
    }

    #[test]
    fn test_parse_javascript() -> Result<()> {
        let temp_dir = tempdir()?;
        let file_path = temp_dir.path().join("test.js");

        let content = r#"
function testFunction(arg1, arg2) {
    console.log("Hello");
    return arg1 + arg2;
}

class TestClass {
    method() {
        return true;
    }
}
"#;
        fs::write(&file_path, content)?;

        let mut parser = CodeParser::new()?;
        let definitions = parser.parse_file(&file_path)?;

        assert_eq!(definitions.len(), 3);
        assert!(definitions.iter().any(|d| d.name == "testFunction"));
        assert!(definitions.iter().any(|d| d.name == "TestClass"));
        assert!(definitions.iter().any(|d| d.name == "method"));

        Ok(())
    }
}
