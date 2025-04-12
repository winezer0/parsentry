use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use genai::chat::{ChatMessage, ChatRequest};
use genai::Client;
use log::{info, warn};
use std::path::PathBuf;

use vulnhuntrs::analyzer::analyze_file;
use vulnhuntrs::prompts::{README_SUMMARY_PROMPT_TEMPLATE, SYS_PROMPT_TEMPLATE};
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
async fn main() -> Result<()> {
    env_logger::init();
    dotenv().ok();

    let args = Args::parse();
    let repo = RepoOps::new(args.root.clone());

    println!("\n🔍 Vulnhuntrs - セキュリティ解析ツール\n");

    let files = repo.get_relevant_files();
    println!("📁 関連するソースファイルを検出しました");

    let files_to_analyze = if let Some(analyze_path) = args.analyze {
        repo.get_files_to_analyze(Some(analyze_path))?
    } else {
        repo.get_network_related_files(&files)
    };

    let client = Client::default();

    if let Some(readme_content) = repo.get_readme_content() {
        println!("📖 プロジェクトのREADMEを解析中...");
        info!("プロジェクトREADMEを要約中");
        log::debug!("READMEの文字数: {} 文字", readme_content.len());

        let chat_req = ChatRequest::new(vec![
            ChatMessage::system(SYS_PROMPT_TEMPLATE),
            ChatMessage::user(format!(
                "{}\n{}",
                readme_content, README_SUMMARY_PROMPT_TEMPLATE
            )),
        ]);

        log::debug!("README要約リクエストを送信中");
        let chat_res = client.exec_chat(&args.model, chat_req, None).await?;
        let summary = chat_res.content_text_as_str().unwrap_or_default();
        info!("READMEの要約が完了しました");
        log::debug!("受信したREADME要約の文字数: {} 文字", summary.len());
    } else {
        warn!("READMEが見つかりませんでした");
    }

    for file_path in files_to_analyze {
        let file_name = file_path.display().to_string();
        println!("\n📄 解析対象: {}\n", file_name);
        println!("{}", "=".repeat(80));

        let analysis_result = analyze_file(&file_path, &args.model, &files, args.verbosity).await?;

        analysis_result.print_readable();
    }

    println!("\n✅ 解析が完了しました\n");

    Ok(())
}
