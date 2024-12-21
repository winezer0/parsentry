use anyhow::Result;
use log::{debug, trace};
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
        let mut parser = Parser::new();

        // 脆弱性パターンを含むクエリを追加
        let languages = vec![
            unsafe {
                (
                    tree_sitter_python(),
                    "python",
                    r#"[
                (function_definition
                    name: (identifier) @def.name
                ) @def.function
                (class_definition
                    name: (identifier) @def.name
                ) @def.class
                (call
                    function: (attribute
                        object: (identifier) @vuln.object
                        attribute: (identifier) @vuln.method
                    )
                ) @vuln.call
                (call
                    function: (identifier) @vuln.func
                ) @vuln.call
                ; Command injection specific patterns
                (call
                    function: (attribute
                        object: (identifier) @cmd.object
                        attribute: (identifier) @cmd.method
                    )
                    [
                        (argument_list
                            (string) @cmd.arg
                        )
                        (argument_list
                            (binary_operator) @cmd.arg
                        )
                        (argument_list
                            (identifier) @cmd.arg
                        )
                    ]
                ) @cmd.call
            ]"#,
                )
            },
            unsafe {
                (
                    tree_sitter_javascript(),
                    "javascript",
                    r#"[
                (function_declaration
                    name: (identifier) @def.name
                ) @def.function
                (class_declaration
                    name: (identifier) @def.name
                ) @def.class
                (call_expression
                    function: (member_expression
                        property: (property_identifier) @vuln.method
                    )
                ) @vuln.call
                (call_expression
                    function: (identifier) @vuln.func
                ) @vuln.call
            ]"#,
                )
            },
            unsafe {
                (
                    tree_sitter_typescript(),
                    "typescript",
                    r#"[
                (function_declaration
                    name: (identifier) @def.name
                ) @def.function
                (class_declaration
                    name: (identifier) @def.name
                ) @def.class
                (call_expression
                    function: (member_expression
                        property: (property_identifier) @vuln.method
                    )
                ) @vuln.call
                (call_expression
                    function: (identifier) @vuln.func
                ) @vuln.call
            ]"#,
                )
            },
            unsafe {
                (
                    tree_sitter_rust(),
                    "rust",
                    r#"[
                (function_item
                    name: (identifier) @def.name
                ) @def.function
                (struct_item
                    name: (type_identifier) @def.name
                ) @def.struct
                (macro_invocation
                    macro: (identifier) @vuln.func
                ) @vuln.call
            ]"#,
                )
            },
            unsafe {
                (
                    tree_sitter_go(),
                    "go",
                    r#"[
                (function_declaration
                    name: (identifier) @def.name
                ) @def.function
                (type_declaration
                    name: (type_identifier) @def.name
                ) @def.type
                (call_expression
                    function: (selector_expression
                        field: (field_identifier) @vuln.method
                    )
                ) @vuln.call
                (call_expression
                    function: (identifier) @vuln.func
                ) @vuln.call
            ]"#,
                )
            },
            unsafe {
                (
                    tree_sitter_java(),
                    "java",
                    r#"[
                (method_declaration
                    name: (identifier) @def.name
                ) @def.method
                (class_declaration
                    name: (identifier) @def.name
                ) @def.class
                (method_invocation
                    name: (identifier) @vuln.method
                ) @vuln.call
            ]"#,
                )
            },
        ];

        for (lang, _, _) in &languages {
            parser.set_language(*lang)?;
        }

        Ok(Self { parser, languages })
    }

    pub fn parse_file(&mut self, path: &Path) -> Result<Vec<Definition>> {
        let content = std::fs::read_to_string(path)?;
        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        debug!("Parsing file with extension: {}", extension);
        trace!("File content:\n{}", content);

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
        let tree = self
            .parser
            .parse(&content, None)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse file: {}", path.display()))?;

        let query = Query::new(language.0, language.2)?;
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), content.as_bytes());

        let mut definitions = Vec::new();
        for match_ in matches {
            debug!("Found match with pattern index: {}", match_.pattern_index);

            for capture in match_.captures {
                let def_node = capture.node;
                let capture_name = query.capture_names().get(capture.index as usize);

                trace!(
                    "Processing capture: {:?} with text: {:?}",
                    capture_name,
                    def_node.utf8_text(content.as_bytes()).ok()
                );

                // Get the name based on the capture name
                let name = match capture_name {
                    Some(name) => {
                        let node_text = def_node.utf8_text(content.as_bytes())?;
                        debug!("Found node: {} - {}", name, node_text);
                        format!("{} - {}", name, node_text)
                    }
                    None => continue,
                };

                if !name.is_empty() {
                    debug!("Adding definition: {}", name);
                    definitions.push(Definition {
                        name,
                        start_byte: def_node.start_byte(),
                        end_byte: def_node.end_byte(),
                    });
                }
            }
        }

        debug!("Found {} definitions", definitions.len());
        trace!("Definitions: {:?}", definitions);
        Ok(definitions)
    }

    pub fn get_definition_source(&self, path: &Path, def: &Definition) -> Result<String> {
        let content = std::fs::read_to_string(path)?;
        Ok(content[def.start_byte..def.end_byte].to_string())
    }
}
