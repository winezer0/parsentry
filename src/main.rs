use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use std::path::PathBuf;
use vulnhuntrs::analyzer::analyze_file;
use vulnhuntrs::security_patterns::SecurityRiskPatterns;

use vulnhuntrs::repo::RepoOps;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the root directory of the project
    #[arg(short, long)]
    root: PathBuf,

    /// Specific path or file within the project to analyze
    #[arg(short, long)]
    analyze: Option<PathBuf>,

    /// LLM model to use (default: gpt-4o-2024-08-06)
    #[arg(short, long, default_value = "gpt-4o-2024-08-06")]
    model: String,

    /// Increase output verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Enable evaluation mode for example vulnerable apps
    #[arg(short, long)]
    evaluate: bool,
}

#[tokio::main]
/// コマンドライン引数をパースし、リポジトリ内の関連ファイルを解析してレポートを出力するエントリポイント。
async fn main() -> Result<()> {
    env_logger::init();
    dotenv().ok();

    let args = Args::parse();
    let mut repo = RepoOps::new(args.root.clone());

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
    let patterns = SecurityRiskPatterns::new();
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

        analysis_result.print_readable();
    }

    println!("✅ 解析が完了しました");

    Ok(())
}
