use git2::{Cred, Error, FetchOptions, RemoteCallbacks, Repository};
use std::env;
use std::path::Path;

/// GitHubリポジトリをcloneする
///
/// # 引数
/// - repo: "owner/repo" 形式のGitHubリポジトリ名
/// - dest: clone先ディレクトリ
///
/// # 戻り値
/// - Ok(()) 成功
/// - Err(Error) 失敗
pub fn clone_github_repo(repo: &str, dest: &Path) -> Result<(), Error> {
    // 既存ディレクトリがあればエラー
    if dest.exists() {
        return Err(Error::from_str("Destination directory already exists"));
    }

    // GitHubリポジトリURL組み立て
    let url = format!("https://github.com/{}.git", repo);

    // GITHUB_TOKENがあれば認証付き
    let token = env::var("GITHUB_TOKEN").ok();

    let mut callbacks = RemoteCallbacks::new();
    if let Some(ref token) = token {
        callbacks.credentials(move |_url, _username_from_url, _allowed_types| {
            Cred::userpass_plaintext("x-access-token", token)
        });
    }

    let mut fetch_options = FetchOptions::new();
    if token.is_some() {
        fetch_options.remote_callbacks(callbacks);
    }

    // 空リポジトリ作成
    let repo = Repository::init(dest)?;
    // origin remote 作成
    let mut remote = repo.remote("origin", &url)?;

    // fetch
    remote.fetch(
        &["refs/heads/*:refs/remotes/origin/*"],
        Some(&mut fetch_options),
        None,
    )?;

    // HEAD をセット
    let fetch_head = repo.find_reference("FETCH_HEAD")?;
    let fetch_commit = fetch_head.peel_to_commit()?;
    repo.branch("master", &fetch_commit, true)?;
    repo.set_head("refs/heads/master")?;
    repo.checkout_head(None)?;

    Ok(())
}
