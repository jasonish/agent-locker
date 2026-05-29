use std::env;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::builder::styling::{AnsiColor, Reset, Style};

use crate::Result;
use crate::cli::{Cli, GitAccess, Mode};
use crate::config::Config;
use crate::git;

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: std::ffi::OsString,
    pub args: Vec<std::ffi::OsString>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub context_dir: PathBuf,
    pub write_dirs: Vec<PathBuf>,
    pub command: CommandSpec,
    pub mode: Mode,
}

impl Policy {
    pub fn from_cli(cli: Cli) -> Result<Self> {
        let cwd = env::current_dir()?;
        let config = Config::load()?;
        let context_dir = match cli.context_dir {
            Some(path) => normalize_path(&cwd, &path),
            None => resolve_context_root(&cwd, &config).unwrap_or_else(|| cwd.clone()),
        };

        let git_access = resolve_git_access(cli.git_access, &config);

        let mut write_dirs = vec![context_dir.clone()];
        if let Some(real_git_dir) = git::detect_real_git_dir(&context_dir) {
            if grant_git_dir(git_access, &real_git_dir) {
                write_dirs.push(real_git_dir);
            }
        }

        match cli.mode {
            Mode::Opencode => {
                for path in [
                    "~/.opencode",
                    "~/.local/share/opencode",
                    "~/.cache/opencode",
                ] {
                    write_dirs.push(expand_path(path, &cwd));
                }
            }
            Mode::Claude => {
                write_dirs.push(expand_path("~/.claude", &cwd));
                write_dirs.push(expand_path("~/.claude.json", &cwd));
            }
            Mode::Codex => write_dirs.push(expand_path("~/.codex", &cwd)),
        }

        // Temp space is needed by every command.
        write_dirs.push(PathBuf::from("/tmp"));

        // Coding agents need to write only to the null device and the
        // controlling terminal; nothing else under /dev, and not the XDG
        // runtime directory. This was verified for claude via strace and is
        // applied to every preset and to generic commands to keep the
        // writable device surface minimal. Reads elsewhere (e.g.
        // /dev/urandom) still work because the whole filesystem is readable.
        write_dirs.push(PathBuf::from("/dev/null"));
        write_dirs.push(PathBuf::from("/dev/tty"));

        let command = build_command(
            cli.mode,
            &cli.command_and_args,
            config.preset_args(cli.mode),
        );

        dedup_paths(&mut write_dirs);

        Ok(Self {
            context_dir,
            write_dirs,
            command,
            mode: cli.mode,
        })
    }

    /// Human-readable summary of the sandbox printed on every startup.
    pub fn render_banner(&self, color: bool) -> String {
        let (label, label_off) = paint(AnsiColor::Cyan.on_default().bold(), color);
        let home = env::var_os("HOME").map(PathBuf::from);

        let mut out = String::new();
        let _ = writeln!(
            out,
            "{label}Context root:{label_off} {}",
            display_path(&self.context_dir, home.as_deref())
        );
        let _ = writeln!(out, "{label}Writable:{label_off}");
        for group in group_by_parent(&self.write_dirs) {
            let rendered: Vec<String> = group
                .iter()
                .map(|path| display_path(path, home.as_deref()))
                .collect();
            if rendered.len() == 1 {
                let _ = writeln!(out, "  - {}", rendered[0]);
            } else {
                let _ = writeln!(out, "  - [{}]", rendered.join(", "));
            }
        }

        let mut command = self.command.program.to_string_lossy().into_owned();
        for arg in &self.command.args {
            command.push(' ');
            command.push_str(&arg.to_string_lossy());
        }
        let _ = writeln!(out, "{label}Starting:{label_off} {command}");

        out
    }
}

/// Renders a path for display, replacing a leading `$HOME` with `~`.
fn display_path(path: &Path, home: Option<&Path>) -> String {
    if let Some(home) = home {
        if let Ok(rest) = path.strip_prefix(home) {
            if rest.as_os_str().is_empty() {
                return "~".to_string();
            }
            return format!("~/{}", rest.display());
        }
    }
    path.display().to_string()
}

/// Groups consecutive paths that share the same parent directory, so related
/// entries (e.g. `/dev/null` and `/dev/tty`) render together. The filesystem
/// root is never used as a grouping parent, keeping top-level paths like
/// `/tmp` and `/dev` on their own lines.
fn group_by_parent(paths: &[PathBuf]) -> Vec<Vec<PathBuf>> {
    let mut groups: Vec<Vec<PathBuf>> = Vec::new();
    for path in paths {
        let parent = path.parent();
        let groupable = parent.is_some_and(|p| !p.as_os_str().is_empty() && p != Path::new("/"));
        let merged = match groups.last_mut() {
            Some(last) if groupable && last.first().and_then(|p| p.parent()) == parent => {
                last.push(path.clone());
                true
            }
            _ => false,
        };
        if !merged {
            groups.push(vec![path.clone()]);
        }
    }
    groups
}

/// Returns the SGR start/reset pair for `style`, or empty strings when color
/// is disabled.
fn paint(style: Style, color: bool) -> (String, String) {
    if color {
        (style.render().to_string(), Reset.render().to_string())
    } else {
        (String::new(), String::new())
    }
}

/// Builds the command to run. The agent's program is fixed by the mode; its
/// arguments are the configured extra arguments (from the config file)
/// followed by anything passed on the command line. Agents run in their
/// default mode unless the config opts in to flags like
/// `--dangerously-skip-permissions`.
fn build_command(mode: Mode, input: &[std::ffi::OsString], extra: &[String]) -> CommandSpec {
    let program = match mode {
        Mode::Opencode => "opencode",
        Mode::Claude => "claude",
        Mode::Codex => "codex",
    };
    let mut args: Vec<std::ffi::OsString> = extra.iter().map(std::ffi::OsString::from).collect();
    args.extend_from_slice(input);
    CommandSpec {
        program: std::ffi::OsString::from(program),
        args,
    }
}

/// Picks the context directory from the configured context roots when no
/// explicit `-C` was given. A root matches when the current directory is the
/// root itself or lives beneath it; the deepest (most specific) matching root
/// wins. Returns `None` when nothing matches, leaving the caller to fall back
/// to the current directory.
fn resolve_context_root(cwd: &Path, config: &Config) -> Option<PathBuf> {
    let cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let roots: Vec<PathBuf> = config
        .context_roots()
        .iter()
        .map(|root| normalize_path(&cwd, Path::new(root)))
        .collect();
    deepest_containing_root(&cwd, &roots)
}

/// From `roots`, returns the one that contains `cwd` (or equals it) and has the
/// most path components, i.e. the most specific match. All paths are compared
/// lexically, so callers should canonicalize first.
fn deepest_containing_root(cwd: &Path, roots: &[PathBuf]) -> Option<PathBuf> {
    roots
        .iter()
        .filter(|root| cwd.starts_with(root))
        .max_by_key(|root| root.components().count())
        .cloned()
}

/// Resolves the effective git-access policy. An explicit command-line choice
/// (`--allow-parent-git` / `--no-allow-parent-git`) always wins; otherwise the
/// `allow_parent_git` config default applies; with neither, we prompt.
fn resolve_git_access(cli: GitAccess, config: &Config) -> GitAccess {
    match cli {
        GitAccess::Ask => match config.allow_parent_git() {
            Some(true) => GitAccess::Allow,
            Some(false) => GitAccess::Deny,
            None => GitAccess::Ask,
        },
        explicit => explicit,
    }
}

/// Decides whether to grant write access to a detected worktree's parent git
/// directory. `Allow`/`Deny` are honored directly; `Ask` prompts on the
/// terminal, defaulting to deny when there is nothing to prompt (no TTY, EOF,
/// or an empty/negative answer).
fn grant_git_dir(access: GitAccess, git_dir: &Path) -> bool {
    match access {
        GitAccess::Allow => true,
        GitAccess::Deny => false,
        GitAccess::Ask => prompt_git_dir(git_dir),
    }
}

fn prompt_git_dir(git_dir: &Path) -> bool {
    use std::io::{IsTerminal, stderr, stdin};

    let home = env::var_os("HOME").map(PathBuf::from);
    let shown = display_path(git_dir, home.as_deref());

    // Fall back to a read-only default when there is no terminal to drive the
    // interactive prompt (e.g. run from a script or with stdin redirected).
    if !stdin().is_terminal() || !stderr().is_terminal() {
        eprintln!(
            "agent-locker: git worktree detected; leaving its parent git \
             directory ({shown}) read-only (no terminal to prompt). Pass \
             --allow-parent-git to grant write access."
        );
        return false;
    }

    // On cancel (Esc/Ctrl-C) or any prompt error, default to deny.
    inquire::Confirm::new("git worktree detected — grant write access to its parent git directory?")
        .with_default(false)
        .with_help_message(&shown)
        .prompt()
        .unwrap_or(false)
}

fn dedup_paths(paths: &mut Vec<PathBuf>) {
    let mut seen = std::collections::BTreeSet::new();
    paths.retain(|path| seen.insert(path.clone()));
}

fn normalize_path(cwd: &Path, path: &Path) -> PathBuf {
    let expanded = expand_os_path(path, cwd);
    expanded.canonicalize().unwrap_or(expanded)
}

fn expand_path(path: &str, cwd: &Path) -> PathBuf {
    expand_os_path(Path::new(path), cwd)
}

fn expand_os_path(path: &Path, cwd: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" || raw.starts_with("~/") {
        if let Some(home) = env::var_os("HOME") {
            let suffix = raw.strip_prefix('~').unwrap_or("");
            PathBuf::from(home).join(suffix.trim_start_matches('/'))
        } else {
            path.to_path_buf()
        }
    } else if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(roots: &[&str]) -> Vec<PathBuf> {
        roots.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn no_roots_means_no_match() {
        assert_eq!(
            deepest_containing_root(Path::new("/home/u/oisf/dev/x"), &[]),
            None
        );
    }

    #[test]
    fn matches_when_cwd_is_below_root() {
        let roots = paths(&["/home/u/oisf/dev"]);
        assert_eq!(
            deepest_containing_root(Path::new("/home/u/oisf/dev/suricata/src"), &roots),
            Some(PathBuf::from("/home/u/oisf/dev")),
        );
    }

    #[test]
    fn matches_when_cwd_equals_root() {
        let roots = paths(&["/home/u/oisf/dev"]);
        assert_eq!(
            deepest_containing_root(Path::new("/home/u/oisf/dev"), &roots),
            Some(PathBuf::from("/home/u/oisf/dev")),
        );
    }

    #[test]
    fn deepest_root_wins() {
        let roots = paths(&["/home/u/oisf", "/home/u/oisf/dev"]);
        assert_eq!(
            deepest_containing_root(Path::new("/home/u/oisf/dev/suricata"), &roots),
            Some(PathBuf::from("/home/u/oisf/dev")),
        );
    }

    #[test]
    fn no_match_outside_any_root() {
        let roots = paths(&["/home/u/oisf/dev"]);
        assert_eq!(
            deepest_containing_root(Path::new("/home/u/other"), &roots),
            None
        );
    }

    #[test]
    fn sibling_prefix_does_not_match() {
        // `/home/u/oisf/dev` must not match `/home/u/oisf/development`.
        let roots = paths(&["/home/u/oisf/dev"]);
        assert_eq!(
            deepest_containing_root(Path::new("/home/u/oisf/development"), &roots),
            None,
        );
    }
}
