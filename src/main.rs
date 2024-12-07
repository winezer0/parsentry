mod analyzer;
mod llm;
mod parser;
mod prompts;
mod repo;
mod response;
mod symbol_finder;

use anyhow::Result;
use clap::Parser;
use log::{info, warn};
use std::path::PathBuf;

use analyzer::analyze_file;
use llm::initialize_llm;
use prompts::{README_SUMMARY_PROMPT_TEMPLATE, SYS_PROMPT_TEMPLATE};
use repo::RepoOps;
use symbol_finder::SymbolExtractor;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the root directory of the project
    #[arg(short, long)]
    root: PathBuf,

    /// Specific path or file within the project to analyze
    #[arg(short, long)]
    analyze: Option<PathBuf>,

    /// LLM client to use (default: claude)
    #[arg(short, long, default_value = "claude")]
    llm: String,

    /// Increase output verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbosity: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    dotenv::dotenv().ok();

    let args = Args::parse();
    let repo = RepoOps::new(args.root.clone());
    let mut code_extractor = SymbolExtractor::new(&args.root);

    println!("\n🔍 Vulnhuntrs - Security Analysis Tool\n");

    // Get repo files that don't include tests and documentation
    let files = repo.get_relevant_files();
    println!("📁 Found relevant source files");

    // Get files to analyze based on command line args
    let files_to_analyze = if let Some(analyze_path) = args.analyze {
        repo.get_files_to_analyze(Some(analyze_path))?
    } else {
        repo.get_network_related_files(&files)
    };

    // Read README content
    let mut system_prompt = SYS_PROMPT_TEMPLATE.to_string();
    if let Some(readme_content) = repo.get_readme_content() {
        println!("📖 Analyzing project README...");
        info!("Summarizing project README");
        let llm = initialize_llm(&args.llm, "")?;
        let summary = llm
            .chat(&format!(
                "{}\n{}",
                readme_content, README_SUMMARY_PROMPT_TEMPLATE
            ))
            .await?;
        info!("README summary complete");
        system_prompt = format!("{}\n\nProject Context:\n{}", system_prompt, summary);
    } else {
        warn!("No README summary found");
    }

    let llm = initialize_llm(&args.llm, &system_prompt)?;

    for file_path in files_to_analyze {
        let file_name = file_path.display().to_string();
        println!("\n📄 Analyzing: {}\n", file_name);
        println!("{}", "=".repeat(80));

        let analysis_result = analyze_file(
            &file_path,
            &llm,
            &mut code_extractor,
            &files,
            args.verbosity,
        )
        .await?;

        // Print vulnerability types
        println!("\n🔒 Vulnerability Types:");
        for vuln_type in &analysis_result.vulnerability_types {
            println!("  • {:?}", vuln_type);
        }

        // Print confidence score
        println!(
            "\n📊 Confidence Score: {}%",
            analysis_result.confidence_score
        );
        println!("{}", "-".repeat(80));

        // Print analysis details
        println!("\n📝 Details:");
        for line in analysis_result.analysis.lines() {
            let line = line.trim();
            if !line.is_empty() {
                println!("  {}", line);
            }
        }
        println!("{}", "-".repeat(80));

        // Print PoC if available
        if !analysis_result.poc.is_empty() {
            println!("\n🔬 Proof of Concept:");
            for line in analysis_result.poc.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    println!("  {}", line);
                }
            }
            println!("{}", "-".repeat(80));
        }

        // Print context code
        if !analysis_result.context_code.is_empty() {
            println!("\n💻 Relevant Code:");
            for context in &analysis_result.context_code {
                println!("  • {}", context.name);
                println!("    Reason: {}", context.reason);
                println!("    Line: {}\n", context.code_line);
            }
            println!("{}", "-".repeat(80));
        }

        println!("\nPress Enter to continue...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
    }

    println!("\n✅ Analysis complete!\n");

    Ok(())
}
