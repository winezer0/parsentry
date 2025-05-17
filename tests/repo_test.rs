use tempfile::tempdir;
use vulnhuntrs::repo::RepoOps;

#[test]
fn test_ruby_files_are_recognized() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("test.rb");
    std::fs::write(&file_path, "puts 'hello'")?;

    let repo = RepoOps::new(dir.path().to_path_buf());
    let files = repo.get_relevant_files();

    assert!(files.contains(&file_path));
    Ok(())
}
