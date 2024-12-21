use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use genai::chat::{ChatMessage, ChatOptions, ChatRequest, ChatResponseFormat};
use genai::{Client, ClientConfig};
use log::{info, warn};
use std::path::PathBuf;

use vulnhuntrs::analyzer::analyze_file;
use vulnhuntrs::prompts::{README_SUMMARY_PROMPT_TEMPLATE, SYS_PROMPT_TEMPLATE};
use vulnhuntrs::repo::RepoOps;
use vulnhuntrs::symbol_finder::SymbolExtractor;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the root directory of the project
    #[arg(short, long)]
    root: PathBuf,

    /// Specific path or file within the project to analyze
    #[arg(short, long)]
    analyze: Option<PathBuf>,

    /// LLM model to use (default: claude-3-haiku-20240307)
    #[arg(short, long, default_value = "claude-3-haiku-20240307")]
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
    let mut code_extractor = SymbolExtractor::new(&args.root);

    println!("\n🔍 Vulnhuntrs - Security Analysis Tool\n");

    // Get repo files excluding tests and documentation
    let files = repo.get_relevant_files();
    println!("📁 Found relevant source files");

    // Get files to analyze based on command line args
    // If no specific path is provided, analyze files with potential security risks
    let files_to_analyze = if let Some(analyze_path) = args.analyze {
        repo.get_files_to_analyze(Some(analyze_path))?
    } else {
        repo.get_network_related_files(&files)
    };

    // Initialize genai client
    let client = Client::default();

    // Read README content
    // let system_prompt = SYS_PROMPT_TEMPLATE.to_string();
    if let Some(readme_content) = repo.get_readme_content() {
        println!("📖 Analyzing project README...");
        info!("Summarizing project README");
        log::debug!("README content length: {} characters", readme_content.len());

        let chat_req = ChatRequest::new(vec![
            ChatMessage::system(SYS_PROMPT_TEMPLATE),
            ChatMessage::user(format!(
                "{}\n{}",
                readme_content, README_SUMMARY_PROMPT_TEMPLATE
            )),
        ]);

        log::debug!("Sending README summary request");
        let chat_res = client.exec_chat(&args.model, chat_req, None).await?;
        let summary = chat_res.content_text_as_str().unwrap_or_default();
        info!("README summary complete");
        log::debug!("Received README summary of {} characters", summary.len());
        // system_prompt = format!("{}\n\nProject Context:\n{}", system_prompt, summary);
    } else {
        warn!("No README summary found");
    }

    for file_path in files_to_analyze {
        let file_name = file_path.display().to_string();
        println!("\n📄 Analyzing: {}\n", file_name);
        println!("{}", "=".repeat(80));

        let analysis_result = analyze_file(
            &file_path,
            &args.model,
            &mut code_extractor,
            &files,
            args.verbosity,
        )
        .await?;

        analysis_result.print_readable();

        println!("\nPress Enter to continue...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
    }

    println!("\n✅ Analysis complete!\n");

    Ok(())
}
