use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Language as TreeSitterLanguage, Query, QueryCursor, Parser};
use streaming_iterator::StreamingIterator;

unsafe extern "C" {
    fn tree_sitter_c() -> tree_sitter::Language;
    fn tree_sitter_cpp() -> tree_sitter::Language;
    fn tree_sitter_python() -> tree_sitter::Language;
    fn tree_sitter_javascript() -> tree_sitter::Language;
    fn tree_sitter_typescript() -> tree_sitter::Language;
    fn tree_sitter_java() -> tree_sitter::Language;
    fn tree_sitter_go() -> tree_sitter::Language;
    fn tree_sitter_ruby() -> tree_sitter::Language;
    fn tree_sitter_rust() -> tree_sitter::Language;
    fn tree_sitter_hcl() -> tree_sitter::Language;
    fn tree_sitter_php() -> tree_sitter::Language;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Language {
    Python,
    JavaScript,
    Rust,
    TypeScript,
    Java,
    Go,
    Ruby,
    C,
    Cpp,
    Terraform,
    CloudFormation,
    Kubernetes,
    Yaml,
    Bash,
    Shell,
    Php,
    Other,
}

impl Language {
    pub fn from_extension(ext: &str) -> Self {
        match ext {
            "py" => Language::Python,
            "js" => Language::JavaScript,
            "rs" => Language::Rust,
            "ts" => Language::TypeScript,
            "java" => Language::Java,
            "go" => Language::Go,
            "rb" => Language::Ruby,
            "c" | "h" => Language::C,
            "cpp" | "cxx" | "cc" | "hpp" | "hxx" => Language::Cpp,
            "tf" | "hcl" => Language::Terraform,
            "yml" | "yaml" => Language::Yaml,
            "sh" | "bash" => Language::Bash,
            "php" | "php3" | "php4" | "php5" | "phtml" => Language::Php,
            _ => Language::Other,
        }
    }

    pub fn from_filename(filename: &str) -> Self {
        // Extract extension and use existing logic
        if let Some(ext) = std::path::Path::new(filename)
            .extension()
            .and_then(|e| e.to_str())
        {
            Self::from_extension(ext)
        } else {
            Language::Other
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternType {
    Principal, // Who: user input (Programming) | AWS account/role (IaC)
    Action,    // What: operations/methods (Programming) | API actions (IaC)
    Resource,  // Where: files/databases (Programming) | AWS resources (IaC)
}

#[derive(Debug, Clone, Deserialize)]
pub struct PatternConfig {
    #[serde(flatten)]
    pub pattern_type: PatternQuery,
    pub description: String,
    pub attack_vector: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PatternQuery {
    Definition { definition: String },
    Reference { reference: String },
}

#[derive(Debug, Clone, Deserialize)]
pub struct LanguagePatterns {
    pub principals: Option<Vec<PatternConfig>>, // Who (sources of authority/input)
    pub actions: Option<Vec<PatternConfig>>,    // What (operations/permissions)
    pub resources: Option<Vec<PatternConfig>>,  // Where (targets/sinks)
}

pub struct SecurityRiskPatterns {
    principal_definition_queries: Vec<Query>,
    principal_reference_queries: Vec<Query>,
    action_definition_queries: Vec<Query>,
    action_reference_queries: Vec<Query>,
    resource_definition_queries: Vec<Query>,
    resource_reference_queries: Vec<Query>,
    language: TreeSitterLanguage,
    pattern_configs: Vec<PatternConfig>,
}

#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub pattern_config: PatternConfig,
    pub pattern_type: PatternType,
    pub start_byte: usize,
    pub end_byte: usize,
    pub matched_text: String,
}

impl SecurityRiskPatterns {
    pub fn new(language: Language) -> Self {
        Self::new_with_root(language, None)
    }

    pub fn new_with_root(language: Language, root_dir: Option<&Path>) -> Self {
        let pattern_map = Self::load_patterns(root_dir);
        let lang_patterns = pattern_map
            .get(&language)
            .or_else(|| pattern_map.get(&Language::Other))
            .unwrap_or(&LanguagePatterns {
                principals: None,
                actions: None,
                resources: None,
            });

        let ts_language = Self::get_tree_sitter_language(language);

        let mut principal_definition_queries = Vec::new();
        let mut principal_reference_queries = Vec::new();
        let mut action_definition_queries = Vec::new();
        let mut action_reference_queries = Vec::new();
        let mut resource_definition_queries = Vec::new();
        let mut resource_reference_queries = Vec::new();
        let mut pattern_configs = Vec::new();

        if let Some(principals) = &lang_patterns.principals {
            for config in principals {
                pattern_configs.push(config.clone());
                match &config.pattern_type {
                    PatternQuery::Definition { definition } => {
                        if let Ok(query) = Query::new(&ts_language, definition) {
                            principal_definition_queries.push(query);
                        }
                    }
                    PatternQuery::Reference { reference } => {
                        if let Ok(query) = Query::new(&ts_language, reference) {
                            principal_reference_queries.push(query);
                        }
                    }
                }
            }
        }

        if let Some(actions) = &lang_patterns.actions {
            for config in actions {
                pattern_configs.push(config.clone());
                match &config.pattern_type {
                    PatternQuery::Definition { definition } => {
                        if let Ok(query) = Query::new(&ts_language, definition) {
                            action_definition_queries.push(query);
                        }
                    }
                    PatternQuery::Reference { reference } => {
                        if let Ok(query) = Query::new(&ts_language, reference) {
                            action_reference_queries.push(query);
                        }
                    }
                }
            }
        }

        if let Some(resources) = &lang_patterns.resources {
            for config in resources {
                pattern_configs.push(config.clone());
                match &config.pattern_type {
                    PatternQuery::Definition { definition } => {
                        if let Ok(query) = Query::new(&ts_language, definition) {
                            resource_definition_queries.push(query);
                        }
                    }
                    PatternQuery::Reference { reference } => {
                        if let Ok(query) = Query::new(&ts_language, reference) {
                            resource_reference_queries.push(query);
                        }
                    }
                }
            }
        }

        Self {
            principal_definition_queries,
            principal_reference_queries,
            action_definition_queries,
            action_reference_queries,
            resource_definition_queries,
            resource_reference_queries,
            language: ts_language,
            pattern_configs,
        }
    }

    fn get_tree_sitter_language(language: Language) -> TreeSitterLanguage {
        unsafe {
            match language {
                Language::Python => tree_sitter_python(),
                Language::JavaScript => tree_sitter_javascript(),
                Language::TypeScript => tree_sitter_typescript(),
                Language::Rust => tree_sitter_rust(),
                Language::Java => tree_sitter_java(),
                Language::Go => tree_sitter_go(),
                Language::Ruby => tree_sitter_ruby(),
                Language::C => tree_sitter_c(),
                Language::Cpp => tree_sitter_cpp(),
                Language::Terraform => tree_sitter_hcl(),
                Language::Php => tree_sitter_php(),
                _ => tree_sitter_javascript(), // Default fallback
            }
        }
    }

    pub fn matches(&self, content: &str) -> bool {
        let mut parser = Parser::new();
        parser.set_language(&self.language).unwrap();
        
        let tree = match parser.parse(content, None) {
            Some(tree) => tree,
            None => return false,
        };

        let root_node = tree.root_node();

        // Check all query types
        let all_queries = [
            &self.principal_definition_queries,
            &self.principal_reference_queries,
            &self.action_definition_queries,
            &self.action_reference_queries,
            &self.resource_definition_queries,
            &self.resource_reference_queries,
        ];

        for query_set in all_queries {
            for query in query_set {
                let mut cursor = QueryCursor::new();
                let mut matches = cursor.matches(query, root_node, content.as_bytes());
                // Check if there are any matches (predicates are already evaluated by tree-sitter)
                while let Some(match_) = matches.next() {
                    let mut has_valid_capture = false;
                    
                    for capture in match_.captures {
                        let capture_name = &query.capture_names()[capture.index as usize];
                        let node = capture.node;
                        let start_byte = node.start_byte();
                        let end_byte = node.end_byte();
                        let matched_text = content[start_byte..end_byte].to_string();
                        
                        // Filter out variable names with 2 characters or less
                        if matched_text.trim().len() <= 2 {
                            continue;
                        }
                        
                        // For definitions, we want the entire function_definition/class_definition, etc.
                        // For references, we want the specific call/attribute access
                        match *capture_name {
                            "function" | "definition" | "class" | "method_def" | "call" | "expression" | "attribute" => {
                                // Direct structural captures
                                has_valid_capture = true;
                            }
                            "name" | "func" | "attr" | "obj" | "method" => {
                                // These are identifier captures - find the parent node
                                if let Some(parent) = node.parent() {
                                    if parent.kind().contains("definition") || 
                                       parent.kind().contains("declaration") ||
                                       parent.kind().contains("call") ||
                                       parent.kind().contains("attribute") {
                                        // Parent node validation passed
                                    }
                                }
                                has_valid_capture = true;
                            }
                            _ => {
                                // Other captures - use as-is
                                has_valid_capture = true;
                            }
                        }
                    }
                    
                    if has_valid_capture {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn get_pattern_type(&self, content: &str) -> Option<PatternType> {
        let mut parser = Parser::new();
        parser.set_language(&self.language).unwrap();
        
        let tree = match parser.parse(content, None) {
            Some(tree) => tree,
            None => return None,
        };

        let root_node = tree.root_node();

        // Helper function to check if any query matches
        let check_queries = |queries: &[Query]| -> bool {
            for query in queries {
                let mut cursor = QueryCursor::new();
                let mut matches = cursor.matches(query, root_node, content.as_bytes());
                while let Some(match_) = matches.next() {
                    // Check if we have valid captures with sufficient content
                    for capture in match_.captures {
                        let node = capture.node;
                        let start_byte = node.start_byte();
                        let end_byte = node.end_byte();
                        let matched_text = content[start_byte..end_byte].to_string();
                        
                        // Filter out variable names with 2 characters or less
                        if matched_text.trim().len() > 2 {
                            return true;
                        }
                    }
                }
            }
            false
        };

        // Check each pattern type in order
        if check_queries(&self.principal_definition_queries) || check_queries(&self.principal_reference_queries) {
            return Some(PatternType::Principal);
        }
        
        if check_queries(&self.action_definition_queries) || check_queries(&self.action_reference_queries) {
            return Some(PatternType::Action);
        }
        
        if check_queries(&self.resource_definition_queries) || check_queries(&self.resource_reference_queries) {
            return Some(PatternType::Resource);
        }

        None
    }

    pub fn get_attack_vectors(&self, _content: &str) -> Vec<String> {
        // For now, return empty vector - could be enhanced to map tree-sitter queries to attack vectors
        Vec::new()
    }

    pub fn get_pattern_matches(&self, content: &str) -> Vec<PatternMatch> {
        let mut parser = Parser::new();
        parser.set_language(&self.language).unwrap();
        
        let tree = match parser.parse(content, None) {
            Some(tree) => tree,
            None => return Vec::new(),
        };

        let root_node = tree.root_node();
        let mut pattern_matches = Vec::new();
        let content_bytes = content.as_bytes();

        // Helper function to process queries and collect matches
        let mut process_queries = |queries: &[Query], pattern_type: PatternType, _configs: &[PatternConfig], is_definition: bool| {
            for (query_idx, query) in queries.iter().enumerate() {
                let mut cursor = QueryCursor::new();
                let mut matches = cursor.matches(query, root_node, content_bytes);
                
                while let Some(match_) = matches.next() {
                    // Find the best node to capture (full definition/reference context)
                    let mut best_node = None;
                    let mut best_text = String::new();
                    let mut best_priority = 0; // Higher priority = better capture
                    
                    for capture in match_.captures {
                        let capture_name = &query.capture_names()[capture.index as usize];
                        let node = capture.node;
                        let start_byte = node.start_byte();
                        let end_byte = node.end_byte();
                        let matched_text = content[start_byte..end_byte].to_string();
                        
                        // Filter out variable names with 2 characters or less
                        if matched_text.trim().len() <= 2 {
                            continue;
                        }
                        
                        // Assign priority and determine best capture based on type and context
                        let (priority, candidate_node, candidate_text) = match *capture_name {
                            "function" | "definition" | "class" | "method_def" => {
                                // Highest priority - direct captures of full definitions
                                (100, Some(node), matched_text.clone())
                            }
                            "call" | "expression" | "attribute" => {
                                // High priority - direct captures of full expressions  
                                (90, Some(node), matched_text.clone())
                            }
                            "name" | "func" | "attr" | "obj" | "method" => {
                                // Medium priority - identifier captures, find parent
                                let mut found_parent = None;
                                let mut parent = node.parent();
                                while let Some(p) = parent {
                                    if (is_definition && (p.kind().contains("definition") || p.kind().contains("declaration"))) ||
                                       (!is_definition && (p.kind().contains("call") || p.kind().contains("attribute") || p.kind().contains("expression"))) {
                                        found_parent = Some(p);
                                        break;
                                    }
                                    parent = p.parent();
                                }
                                if let Some(p) = found_parent {
                                    (80, Some(p), content[p.start_byte()..p.end_byte()].to_string())
                                } else {
                                    (70, Some(node), matched_text.clone())
                                }
                            }
                            "param" | "func_name" => {
                                // Medium priority - parameter/function name captures, find function definition
                                let mut found_func = None;
                                let mut parent = node.parent();
                                while let Some(p) = parent {
                                    if p.kind() == "function_definition" {
                                        found_func = Some(p);
                                        break;
                                    }
                                    parent = p.parent();
                                }
                                if let Some(p) = found_func {
                                    (85, Some(p), content[p.start_byte()..p.end_byte()].to_string())
                                } else {
                                    (60, Some(node), matched_text.clone())
                                }
                            }
                            _ => {
                                // Low priority - other captures
                                (50, Some(node), matched_text.clone())
                            }
                        };
                        
                        // Update best capture if this one has higher priority
                        if priority > best_priority {
                            best_priority = priority;
                            best_node = candidate_node;
                            best_text = candidate_text;
                        }
                    }
                    
                    if let Some(node) = best_node {
                        let start_byte = node.start_byte();
                        let end_byte = node.end_byte();
                        
                        // Find the corresponding config based on pattern type and index
                        let mut config_idx = 0;
                        for config in &self.pattern_configs {
                            let matches_type = match (&config.pattern_type, is_definition) {
                                (PatternQuery::Definition { .. }, true) => true,
                                (PatternQuery::Reference { .. }, false) => true,
                                _ => false,
                            };
                            
                            if matches_type {
                                let current_pattern_type = self.get_pattern_type_for_config(config);
                                if current_pattern_type == pattern_type {
                                    if config_idx == query_idx {
                                        pattern_matches.push(PatternMatch {
                                            pattern_config: config.clone(),
                                            pattern_type: pattern_type.clone(),
                                            start_byte,
                                            end_byte,
                                            matched_text: best_text.clone(),
                                        });
                                        break;
                                    }
                                    config_idx += 1;
                                }
                            }
                        }
                    }
                }
            }
        };

        // Process all pattern types
        let principals: Vec<PatternConfig> = self.pattern_configs.iter()
            .filter(|c| self.get_pattern_type_for_config(c) == PatternType::Principal)
            .cloned()
            .collect();
        let actions: Vec<PatternConfig> = self.pattern_configs.iter()
            .filter(|c| self.get_pattern_type_for_config(c) == PatternType::Action)
            .cloned()
            .collect();
        let resources: Vec<PatternConfig> = self.pattern_configs.iter()
            .filter(|c| self.get_pattern_type_for_config(c) == PatternType::Resource)
            .cloned()
            .collect();

        process_queries(&self.principal_definition_queries, PatternType::Principal, &principals, true);
        process_queries(&self.principal_reference_queries, PatternType::Principal, &principals, false);
        process_queries(&self.action_definition_queries, PatternType::Action, &actions, true);
        process_queries(&self.action_reference_queries, PatternType::Action, &actions, false);
        process_queries(&self.resource_definition_queries, PatternType::Resource, &resources, true);
        process_queries(&self.resource_reference_queries, PatternType::Resource, &resources, false);

        pattern_matches
    }

    fn get_pattern_type_for_config(&self, config: &PatternConfig) -> PatternType {
        // Determine pattern type based on position in pattern_configs
        let config_position = self.pattern_configs.iter().position(|c| c.description == config.description).unwrap_or(0);
        
        let principals_count = self.principal_definition_queries.len() + self.principal_reference_queries.len();
        let actions_count = self.action_definition_queries.len() + self.action_reference_queries.len();
        
        if config_position < principals_count {
            PatternType::Principal
        } else if config_position < principals_count + actions_count {
            PatternType::Action
        } else {
            PatternType::Resource
        }
    }

    fn load_patterns(root_dir: Option<&Path>) -> HashMap<Language, LanguagePatterns> {
        use Language::*;

        let mut map = HashMap::new();

        // Load patterns from individual language files (tree-sitter only)
        let languages = [
            (Python, include_str!("patterns/python.yml")),
            (JavaScript, include_str!("patterns/javascript.yml")),
            (Rust, include_str!("patterns/rust.yml")),
            (TypeScript, include_str!("patterns/typescript.yml")),
            (Java, include_str!("patterns/java.yml")),
            (Go, include_str!("patterns/go.yml")),
            (Ruby, include_str!("patterns/ruby.yml")),
            (C, include_str!("patterns/c.yml")),
            (Cpp, include_str!("patterns/cpp.yml")),
            (Php, include_str!("patterns/php.yml")),
            // Temporarily disabled regex-based patterns until full migration:
            // (Terraform, include_str!("patterns/terraform.yml")),
            // (Kubernetes, include_str!("patterns/kubernetes.yml")),
            // (Yaml, include_str!("patterns/yaml.yml")),
            // (Bash, include_str!("patterns/bash.yml")),
        ];

        for (lang, content) in languages {
            match serde_yaml::from_str::<LanguagePatterns>(content) {
                Ok(patterns) => {
                    map.insert(lang, patterns);
                }
                Err(e) => {
                    eprintln!("Failed to parse patterns for {:?}: {}", lang, e);
                }
            }
        }

        // Load custom patterns from vuln-patterns.yml if it exists
        Self::load_custom_patterns(&mut map, root_dir);

        map
    }

    fn load_custom_patterns(
        map: &mut HashMap<Language, LanguagePatterns>,
        root_dir: Option<&Path>,
    ) {
        let vuln_patterns_path = if let Some(root) = root_dir {
            root.join("vuln-patterns.yml")
        } else {
            Path::new("vuln-patterns.yml").to_path_buf()
        };

        if vuln_patterns_path.exists() {
            match std::fs::read_to_string(&vuln_patterns_path) {
                Ok(content) => {
                    // Parse the entire file as a map of language names to patterns
                    match serde_yaml::from_str::<HashMap<String, LanguagePatterns>>(&content) {
                        Ok(custom_patterns) => {
                            for (lang_name, patterns) in custom_patterns {
                                // Convert language name to Language enum
                                let language = match lang_name.as_str() {
                                    "Python" => Language::Python,
                                    "JavaScript" => Language::JavaScript,
                                    "TypeScript" => Language::TypeScript,
                                    "Rust" => Language::Rust,
                                    "Java" => Language::Java,
                                    "Go" => Language::Go,
                                    "Ruby" => Language::Ruby,
                                    "C" => Language::C,
                                    "Cpp" => Language::Cpp,
                                    "Terraform" => Language::Terraform,
                                    "CloudFormation" => Language::CloudFormation,
                                    "Kubernetes" => Language::Kubernetes,
                                    "YAML" => Language::Yaml,
                                    "Bash" => Language::Bash,
                                    "Shell" => Language::Shell,
                                    "Php" | "PHP" => Language::Php,
                                    _ => continue,
                                };

                                // Merge custom patterns with existing patterns
                                match map.get_mut(&language) {
                                    Some(existing) => {
                                        // Merge principals
                                        if let Some(custom_principals) = patterns.principals {
                                            match &mut existing.principals {
                                                Some(principals) => {
                                                    principals.extend(custom_principals)
                                                }
                                                None => {
                                                    existing.principals = Some(custom_principals)
                                                }
                                            }
                                        }
                                        // Merge actions
                                        if let Some(custom_actions) = patterns.actions {
                                            match &mut existing.actions {
                                                Some(actions) => actions.extend(custom_actions),
                                                None => existing.actions = Some(custom_actions),
                                            }
                                        }
                                        // Merge resources
                                        if let Some(custom_resources) = patterns.resources {
                                            match &mut existing.resources {
                                                Some(resources) => {
                                                    resources.extend(custom_resources)
                                                }
                                                None => existing.resources = Some(custom_resources),
                                            }
                                        }
                                    }
                                    None => {
                                        // Insert new language patterns
                                        map.insert(language, patterns);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to parse vuln-patterns.yml: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read vuln-patterns.yml: {}", e);
                }
            }
        }
    }
}
