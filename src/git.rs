use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Detects whether `dir` has a `.git` *file* (a linked worktree or a submodule,
/// as opposed to an ordinary repository whose `.git` is a directory) and, if so,
/// returns the real git directory that needs write access for git operations.
///
/// The `.git` file content is untrusted: it can come from a hostile repository
/// that points `gitdir:` at an arbitrary location (e.g. `/` or the home
/// directory) to try to widen the writable set. The resolved path is therefore
/// canonicalized and sanity-checked via [`validate_git_dir`] before being
/// returned. A `.git` file that fails those checks yields `None`, leaving the
/// directory read-only.
pub fn detect_real_git_dir(dir: &Path) -> Option<PathBuf> {
    let git_path = dir.join(".git");
    let metadata = fs::metadata(&git_path).ok()?;
    if !metadata.is_file() {
        return None;
    }

    let first_line = fs::read_to_string(&git_path)
        .ok()?
        .lines()
        .next()?
        .trim()
        .to_string();
    let gitdir = first_line.strip_prefix("gitdir: ")?;

    let resolved = if Path::new(gitdir).is_absolute() {
        PathBuf::from(gitdir)
    } else {
        git_path.parent()?.join(gitdir)
    };

    // For a linked worktree the gitdir points inside the parent repo's
    // `.git/worktrees/<name>`; the directory we actually need writable is the
    // parent `.git` itself. Other `.git`-file layouts (e.g. submodules, whose
    // gitdir is `.git/modules/<name>`) have no `/worktrees/` segment and use the
    // resolved path as-is. `into_owned` drops the borrow so `resolved` can move.
    let resolved_str = resolved.to_string_lossy().into_owned();
    let real = match resolved_str.split_once("/worktrees/") {
        Some((prefix, _)) => PathBuf::from(prefix),
        None => resolved,
    };

    validate_git_dir(real)
}

/// Sanity-checks a path derived from an untrusted `.git` file before it is
/// granted write access. Returns the canonicalized path only if it is an
/// existing directory that looks like a git directory and is not a dangerous
/// top-level location; otherwise warns and returns `None`.
fn validate_git_dir(path: PathBuf) -> Option<PathBuf> {
    // Resolve `..` and symlinks so the checks below (and the eventual Landlock
    // rule) act on the real target rather than the literal string. A path that
    // does not exist cannot be canonicalized, so this also rejects gitdirs
    // pointing at nonexistent locations.
    let path = match path.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            warn_rejected(&path, "cannot be resolved");
            return None;
        }
    };

    if !path.is_dir() {
        warn_rejected(&path, "not a directory");
        return None;
    }

    // A real git directory has a HEAD entry. This rejects a hostile `.git` file
    // that points at an arbitrary location to try to widen the writable set.
    if !path.join("HEAD").exists() {
        warn_rejected(&path, "does not look like a git directory (no HEAD)");
        return None;
    }

    // Defense in depth: never grant the filesystem root or the home directory,
    // even if one somehow contained a HEAD entry.
    if let Some(why) = dangerous_grant_reason(&path, home_dir().as_deref()) {
        warn_rejected(&path, why);
        return None;
    }

    Some(path)
}

/// Canonicalized `$HOME`, or `None` if it is unset, empty, or can't be resolved.
/// Canonicalizing matters because the comparison in [`dangerous_grant_reason`]
/// is against an already-canonical path, so a raw `$HOME` carrying a symlink or
/// trailing slash (e.g. `/home/user/`) would otherwise miss the guard.
fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .and_then(|h| PathBuf::from(h).canonicalize().ok())
}

/// Returns a rejection reason if `path` is a top-level location too dangerous to
/// grant write access to (the filesystem root, or the home directory), else
/// `None`. `path` is expected to be canonicalized; `home` is the canonicalized
/// home directory if known. Pure so it can be tested without mutating `$HOME`.
fn dangerous_grant_reason(path: &Path, home: Option<&Path>) -> Option<&'static str> {
    if path.parent().is_none() {
        return Some("refusing to grant the filesystem root");
    }
    if home == Some(path) {
        return Some("refusing to grant the home directory");
    }
    None
}

fn warn_rejected(path: &Path, why: &str) {
    eprintln!(
        "agent-locker: ignoring git directory from .git file ({}): {why}; \
         leaving its parent git directory read-only",
        path.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal self-cleaning temp directory, to avoid a dev-dependency. Unique
    /// per (test tag, process) so parallel test binaries don't collide.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let base =
                env::temp_dir().join(format!("agent-locker-test-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&base);
            fs::create_dir_all(&base).unwrap();
            TempDir(base)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn make_git_dir(at: &Path) {
        fs::create_dir_all(at).unwrap();
        fs::write(at.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    }

    #[test]
    fn ordinary_repo_with_git_directory_is_not_a_worktree() {
        let tmp = TempDir::new("ordinary");
        let repo = tmp.path().join("repo");
        make_git_dir(&repo.join(".git"));
        assert_eq!(detect_real_git_dir(&repo), None);
    }

    #[test]
    fn valid_worktree_resolves_to_parent_git_dir() {
        let tmp = TempDir::new("worktree");
        let main_git = tmp.path().join("main").join(".git");
        make_git_dir(&main_git);
        fs::create_dir_all(main_git.join("worktrees").join("wt")).unwrap();

        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let gitdir = main_git.join("worktrees").join("wt");
        fs::write(work.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();

        assert_eq!(
            detect_real_git_dir(&work),
            Some(main_git.canonicalize().unwrap()),
        );
    }

    #[test]
    fn hostile_gitdir_pointing_at_non_git_dir_is_rejected() {
        let tmp = TempDir::new("hostile");
        let evil = tmp.path().join("evil");
        fs::create_dir_all(&evil).unwrap(); // exists, but no HEAD

        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join(".git"), format!("gitdir: {}\n", evil.display())).unwrap();

        assert_eq!(detect_real_git_dir(&work), None);
    }

    #[test]
    fn gitdir_pointing_at_nonexistent_path_is_rejected() {
        let tmp = TempDir::new("missing");
        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let missing = tmp.path().join("does-not-exist");
        fs::write(
            work.join(".git"),
            format!("gitdir: {}\n", missing.display()),
        )
        .unwrap();

        assert_eq!(detect_real_git_dir(&work), None);
    }

    #[test]
    fn submodule_gitdir_resolves_to_module_dir_as_is() {
        let tmp = TempDir::new("submodule");
        // A submodule's `.git` file points at `<super>/.git/modules/<name>`,
        // which has no `/worktrees/` segment and is used unchanged.
        let module_git = tmp.path().join("super").join(".git").join("modules").join("sub");
        make_git_dir(&module_git);

        let work = tmp.path().join("super").join("sub");
        fs::create_dir_all(&work).unwrap();
        fs::write(
            work.join(".git"),
            format!("gitdir: {}\n", module_git.display()),
        )
        .unwrap();

        assert_eq!(
            detect_real_git_dir(&work),
            Some(module_git.canonicalize().unwrap()),
        );
    }

    #[test]
    fn home_directory_is_rejected_even_if_it_looks_like_a_git_dir() {
        // Exercised directly (not via `$HOME`) so the test doesn't mutate
        // process-wide env, which is racy under the parallel test runner.
        let tmp = TempDir::new("home");
        let home = tmp.path().canonicalize().unwrap();

        assert_eq!(
            dangerous_grant_reason(&home, Some(&home)),
            Some("refusing to grant the home directory"),
        );
        // A path-with-trailing-slash style mismatch is avoided because both
        // sides are canonicalized; an ordinary git dir below home is allowed.
        let repo = home.join("repo").join(".git");
        assert_eq!(dangerous_grant_reason(&repo, Some(&home)), None);
    }
}
