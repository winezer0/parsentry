use anyhow::Result;
use regex::Regex;
use std::path::PathBuf;

pub struct RepoOps {
    repo_path: PathBuf,
    to_exclude: Vec<String>,
    file_names_to_exclude: Vec<String>,
    compiled_patterns: Vec<Regex>,
    supported_extensions: Vec<String>,
}

impl RepoOps {
    pub fn new(repo_path: PathBuf) -> Self {
        let to_exclude = vec![
            "/setup.py".to_string(),
            "/test".to_string(),
            "/example".to_string(),
            "/docs".to_string(),
            "/site-packages".to_string(),
            ".venv".to_string(),
            "virtualenv".to_string(),
            "/dist".to_string(),
        ];

        let file_names_to_exclude = vec![
            "test_".to_string(),
            "conftest".to_string(),
            "_test.py".to_string(),
        ];

        // Network-related patterns
        let patterns = vec![
            r"async\sdef\s\w+\(.*?request",
            r"gr.Interface\(.*?\)",
            r"@app\.route\(.*?\)",
            // Add more patterns as needed
        ];

        let compiled_patterns = patterns
            .into_iter()
            .map(|p| Regex::new(p).unwrap())
            .collect();

        let supported_extensions = vec![
            "py".to_string(),   // Python
            "js".to_string(),   // JavaScript
            "jsx".to_string(),  // React
            "ts".to_string(),   // TypeScript
            "tsx".to_string(),  // TypeScript React
            "rs".to_string(),   // Rust
            "go".to_string(),   // Go
            "java".to_string(), // Java
        ];

        Self {
            repo_path,
            to_exclude,
            file_names_to_exclude,
            compiled_patterns,
            supported_extensions,
        }
    }

    pub fn get_readme_content(&self) -> Option<String> {
        let patterns = [
            "[Rr][Ee][Aa][Dd][Mm][Ee].[Mm][Dd]",
            "[Rr][Ee][Aa][Dd][Mm][Ee].[Rr][Ss][Tt]",
        ];

        for pattern in patterns {
            if let Ok(entries) = glob::glob(&format!("{}/{}", self.repo_path.display(), pattern)) {
                for entry in entries.flatten() {
                    if let Ok(content) = std::fs::read_to_string(&entry) {
                        return Some(content);
                    }
                }
            }
        }
        None
    }

    pub fn get_relevant_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        let walker = walkdir::WalkDir::new(&self.repo_path);

        for entry in walker.into_iter().filter_map(|e| e.ok()) {
            let path = entry.path().to_path_buf();
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if !self.supported_extensions.contains(&ext_str) {
                    continue;
                }

                let path_str = path.to_string_lossy().to_lowercase();

                if self
                    .to_exclude
                    .iter()
                    .any(|exclude| path_str.contains(exclude))
                {
                    continue;
                }

                if let Some(file_name) = path.file_name() {
                    let file_name = file_name.to_string_lossy().to_lowercase();
                    if self
                        .file_names_to_exclude
                        .iter()
                        .any(|exclude| file_name.contains(exclude))
                    {
                        continue;
                    }
                }

                files.push(path);
            }
        }
        files
    }

    pub fn get_network_related_files(&self, files: &[PathBuf]) -> Vec<PathBuf> {
        let mut network_files = Vec::new();

        for file_path in files {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                if self
                    .compiled_patterns
                    .iter()
                    .any(|pattern| pattern.is_match(&content))
                {
                    network_files.push(file_path.clone());
                }
            }
        }

        network_files
    }

    pub fn get_files_to_analyze(&self, analyze_path: Option<PathBuf>) -> Result<Vec<PathBuf>> {
        let path_to_analyze = analyze_path.unwrap_or_else(|| self.repo_path.clone());

        if path_to_analyze.is_file() {
            if let Some(ext) = path_to_analyze.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if self.supported_extensions.contains(&ext_str) {
                    return Ok(vec![path_to_analyze]);
                }
            }
            Ok(vec![])
        } else if path_to_analyze.is_dir() {
            Ok(walkdir::WalkDir::new(path_to_analyze)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    if let Some(ext) = e.path().extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        self.supported_extensions.contains(&ext_str)
                    } else {
                        false
                    }
                })
                .map(|e| e.path().to_path_buf())
                .collect())
        } else {
            anyhow::bail!(
                "Specified analyze path does not exist: {}",
                path_to_analyze.display()
            )
        }
    }
}
