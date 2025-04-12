use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor}; // Import the trait

extern "C" {
    fn tree_sitter_python() -> Language;
    fn tree_sitter_javascript() -> Language;
    fn tree_sitter_typescript() -> Language;
    fn tree_sitter_tsx() -> Language;
    fn tree_sitter_java() -> Language;
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
        let content = std::fs::read_to_string(path).map_err(|e| {
            anyhow!(
                "ファイルの読み込みに失敗しました: {}: {}",
                path.display(),
                e
            )
        })?;
        self.files.insert(path.to_path_buf(), content.clone());
        Ok(())
    }

    fn get_language(&self, path: &Path) -> Option<Language> {
        let extension = path.extension().and_then(|ext| ext.to_str());
        match extension {
            Some("py") => Some(unsafe { tree_sitter_python() }),
            Some("js") => Some(unsafe { tree_sitter_javascript() }),
            Some("ts") => Some(unsafe { tree_sitter_typescript() }),
            Some("tsx") => Some(unsafe { tree_sitter_tsx() }),
            Some("java") => Some(unsafe { tree_sitter_java() }),
            _ => None,
        }
    }

    fn get_query_path(&self, language: &Language, query_name: &str) -> Result<PathBuf> {
        let lang_name = if language == &unsafe { tree_sitter_python() } {
            "python"
        } else if language == &unsafe { tree_sitter_javascript() } {
            "javascript"
        } else if language == &unsafe { tree_sitter_typescript() }
            || language == &unsafe { tree_sitter_tsx() }
        {
            "typescript"
        } else if language == &unsafe { tree_sitter_java() } {
            "java"
        } else {
            return Err(anyhow!("クエリに対応していない言語です"));
        };

        if lang_name.contains('/') || lang_name.contains('\\') || lang_name.contains("..") {
            return Err(anyhow!("クエリパスの言語名が不正です: {}", lang_name));
        }
        if query_name.contains('/') || query_name.contains('\\') || query_name.contains("..") {
            return Err(anyhow!("クエリパスのクエリ名が不正です: {}", query_name));
        }

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let query_file_name = format!("{}.scm", query_name);
        let query_path = manifest_dir
            .join("custom_queries")
            .join(lang_name)
            .join(&query_file_name);

        if !query_path.exists() {
            return Err(anyhow!(
                "クエリファイルが見つかりません: {}",
                query_path.display()
            ));
        }

        Ok(query_path)
    }

    pub fn find_definition(
        &mut self,
        name: &str,
        source_file: &Path,
    ) -> Result<Option<(PathBuf, Definition)>> {
        let content = self.files.get(source_file).ok_or_else(|| {
            anyhow!(
                "パーサーにファイルが見つかりません: {}",
                source_file.display()
            )
        })?;

        let language = match self.get_language(source_file) {
            Some(lang) => lang,
            None => return Ok(None),
        };

        self.parser
            .set_language(&language)
            .map_err(|e| anyhow!("言語の設定に失敗しました: {}", e))?;

        let tree = self
            .parser
            .parse(content, None)
            .ok_or_else(|| anyhow!("ファイルのパースに失敗しました: {}", source_file.display()))?;

        // Pass language by reference to get_query_path
        let query_path = self.get_query_path(&language, "definitions")?;
        let query_str = fs::read_to_string(&query_path).map_err(|e| {
            anyhow!(
                "クエリファイルの読み込みに失敗しました: {}: {}",
                query_path.display(),
                e
            )
        })?;

        let query = Query::new(&language, &query_str).map_err(|e| {
            anyhow!(
                "クエリの生成に失敗しました: {}: {}",
                query_path.display(),
                e
            )
        })?;

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

            self.parser.set_language(&language).map_err(|e| {
                anyhow!("Failed to set language for {}: {}", file_path.display(), e)
            })?;

            let tree = match self.parser.parse(content, None) {
                Some(t) => t,
                None => {
                    eprintln!(
                        "警告: ファイルのパースに失敗しました: {}",
                        file_path.display()
                    );
                    continue;
                }
            };

            // Pass language by reference to get_query_path
            let query_path = match self.get_query_path(&language, "references") {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "警告: 参照クエリパスの取得に失敗しました: {}: {}",
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
                        "警告: 参照クエリファイルの読み込みに失敗しました: {}: {}",
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
                        "警告: 参照クエリの生成に失敗しました: {}: {}",
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
