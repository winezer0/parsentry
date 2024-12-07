use anyhow::Result;
use regex::Regex;
use std::{
    fs::{self, read_dir},
    path::{Path, PathBuf},
};

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

    fn visit_dirs(&self, dir: &Path, cb: &mut dyn FnMut(&Path)) -> std::io::Result<()> {
        if dir.is_dir() {
            for entry in read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    self.visit_dirs(&path, cb)?;
                } else {
                    cb(&path);
                }
            }
        }
        Ok(())
    }

    pub fn get_readme_content(&self) -> Option<String> {
        let readme_names = ["README.md", "README.MD", "Readme.md", "readme.md"];

        for name in readme_names {
            let readme_path = self.repo_path.join(name);
            if readme_path.exists() {
                if let Ok(content) = fs::read_to_string(&readme_path) {
                    return Some(content);
                }
            }
        }
        None
    }

    pub fn get_relevant_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();

        let mut callback = |path: &Path| {
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if !self.supported_extensions.contains(&ext_str) {
                    return;
                }

                let path_str = path.to_string_lossy().to_lowercase();

                if self
                    .to_exclude
                    .iter()
                    .any(|exclude| path_str.contains(exclude))
                {
                    return;
                }

                if let Some(file_name) = path.file_name() {
                    let file_name = file_name.to_string_lossy().to_lowercase();
                    if self
                        .file_names_to_exclude
                        .iter()
                        .any(|exclude| file_name.contains(exclude))
                    {
                        return;
                    }
                }

                files.push(path.to_path_buf());
            }
        };

        if let Err(e) = self.visit_dirs(&self.repo_path, &mut callback) {
            eprintln!("Error walking directory: {}", e);
        }

        files
    }

    pub fn get_network_related_files(&self, files: &[PathBuf]) -> Vec<PathBuf> {
        let mut network_files = Vec::new();

        for file_path in files {
            if let Ok(content) = fs::read_to_string(file_path) {
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
            let mut files = Vec::new();
            let mut callback = |path: &Path| {
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if self.supported_extensions.contains(&ext_str) {
                        files.push(path.to_path_buf());
                    }
                }
            };

            self.visit_dirs(&path_to_analyze, &mut callback)?;
            Ok(files)
        } else {
            anyhow::bail!(
                "Specified analyze path does not exist: {}",
                path_to_analyze.display()
            )
        }
    }
}
