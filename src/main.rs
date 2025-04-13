use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use std::path::PathBuf;
use vulnhuntrs::analyzer::analyze_file;
use vulnhuntrs::security_patterns::Language;
use vulnhuntrs::security_patterns::SecurityRiskPatterns;

use vulnhuntrs::repo::RepoOps;
use vulnhuntrs::repo_clone::clone_github_repo;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = None,
    group = clap::ArgGroup::new("target")
        .required(true)
        .args(&["root", "repo"])
)]
struct Args {
    /// Path to the root directory of the project
    #[arg(short, long, group = "target")]
    root: Option<PathBuf>,

    /// GitHub repository (owner/repo or URL)
    #[arg(long, group = "target")]
    repo: Option<String>,

    /// Specific path or file within the project to analyze
    #[arg(short, long)]
    analyze: Option<PathBuf>,

    /// LLM model to use (default: o3-mini)
    #[arg(short, long, default_value = "o3-mini")]
    model: String,

    /// Increase output verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Enable evaluation mode for example vulnerable apps
    #[arg(short, long)]
    evaluate: bool,

    /// Output directory for markdown reports
    #[arg(long)]
    output_dir: Option<PathBuf>,
}

#[tokio::main]
/// コマンドライン引数をパースし、リポジトリ内の関連ファイルを解析してレポートを出力するエントリポイント。
async fn main() -> Result<()> {
    env_logger::init();
    dotenv().ok();

    let args = Args::parse();

    // rootディレクトリの決定
    let root_dir = if let Some(repo) = &args.repo {
        // クローン先ディレクトリ名を決定（例: "repo"）
        let dest = PathBuf::from("repo");
        if !dest.exists() {
            println!(
                "🛠️  GitHubリポジトリをクローン中: {} → {}",
                repo,
                dest.display()
            );
            clone_github_repo(repo, &dest)
                .map_err(|e| anyhow::anyhow!("GitHubリポジトリのクローンに失敗: {}", e))?;
        } else {
            println!(
                "⚠️  既にクローン済みディレクトリが存在します: {}",
                dest.display()
            );
        }
        dest
    } else if let Some(root) = &args.root {
        root.clone()
    } else {
        panic!("root path or repo must be set");
    };

    let mut repo = RepoOps::new(root_dir);

    println!("🔍 Vulnhuntrs - セキュリティ解析ツール");

    let files = repo.get_relevant_files();
    println!(
        "📁 関連するソースファイルを検出しました ({}件)",
        files.len()
    );
    for (i, f) in files.iter().enumerate() {
        println!("  [{}] {}", i + 1, f.display());
    }

    // SecurityRiskPatternsで該当ファイルを特定
    let patterns = SecurityRiskPatterns::new(Language::Other);
    let mut pattern_files = Vec::new();
    for file_path in &files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            if patterns.matches(&content) {
                pattern_files.push(file_path.clone());
            }
        }
    }

    println!(
        "🔎 セキュリティパターン該当ファイルを検出しました ({}件)",
        pattern_files.len()
    );
    for (i, f) in pattern_files.iter().enumerate() {
        println!("  [P{}] {}", i + 1, f.display());
    }

    let total = pattern_files.len();
    for (idx, file_path) in pattern_files.iter().enumerate() {
        let file_name = file_path.display().to_string();
        if idx > 0 {
            println!();
        }
        println!("📄 解析対象: {} ({} / {})", file_name, idx + 1, total);
        println!("{}", "=".repeat(80));

        // 関連定義をまとめたContextを構築
        repo.add_file_to_parser(file_path)?;
        let context = repo.collect_context_for_security_pattern(file_path)?;

        // analyze_fileで解析
        let analysis_result =
            analyze_file(file_path, &args.model, &files, args.verbosity, &context).await?;

        // Markdownファイル出力
        if let Some(ref output_dir) = args.output_dir {
            std::fs::create_dir_all(output_dir)?;
            let fname = file_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string() + ".md")
                .unwrap_or_else(|| "report.md".to_string());
            let mut out_path = output_dir.clone();
            out_path.push(fname);
            std::fs::write(&out_path, analysis_result.to_markdown())?;
            println!("📝 Markdownレポートを出力: {}", out_path.display());
        }

        analysis_result.print_readable();
    }

    println!("✅ 解析が完了しました");

    Ok(())
}
