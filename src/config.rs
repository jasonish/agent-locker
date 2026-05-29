use std::env;
use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::Result;
use crate::cli::Mode;

/// On-disk configuration, loaded from `agent-locker/config.toml` under the
/// user's config directory (`$XDG_CONFIG_HOME`, falling back to `~/.config`).
///
/// Each preset section may supply extra arguments that are prepended to the
/// agent's command line, before any arguments given on the command line. This
/// is how a user opts in to flags like `--dangerously-skip-permissions` by
/// default, rather than agent-locker forcing them.
///
/// The top-level `allow_parent_git` key sets the default for a git worktree's
/// parent git directory, so the user is not prompted; the `--allow-parent-git`
/// / `--no-allow-parent-git` flags override it.
///
/// The top-level `context_roots` key lists directories that should become the
/// context (the main writable project directory) whenever the agent is launched
/// anywhere beneath them, widening write access from just the current directory
/// to the whole root. An explicit `-C`/`--context-dir` always overrides this.
///
/// Example `config.toml`:
///
/// ```toml
/// allow_parent_git = true
/// context_roots = ["~/oisf/dev"]
///
/// [claude]
/// args = ["--dangerously-skip-permissions"]
///
/// [codex]
/// args = ["--dangerously-bypass-approvals-and-sandbox"]
/// ```
///
/// Unknown keys are ignored rather than rejected, so a config written for a
/// newer (or older) agent-locker still loads.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    /// Default for granting write access to a worktree's parent git directory.
    /// `None` (key absent) means prompt when a worktree is detected.
    #[serde(default)]
    allow_parent_git: Option<bool>,
    /// Directories that become the context when the current directory is at or
    /// below them. The deepest matching root wins.
    #[serde(default)]
    context_roots: Vec<String>,
    #[serde(default)]
    opencode: PresetConfig,
    #[serde(default)]
    claude: PresetConfig,
    #[serde(default)]
    codex: PresetConfig,
}

#[derive(Debug, Default, Deserialize)]
struct PresetConfig {
    /// Extra arguments prepended to the preset's command line.
    #[serde(default)]
    args: Vec<String>,
}

impl Config {
    /// Loads the config file if present. A missing file yields the default
    /// (empty) configuration; a malformed file is an error.
    pub fn load() -> Result<Self> {
        let Some(path) = config_path() else {
            return Ok(Self::default());
        };
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(err) => {
                return Err(format!("failed to read config {}: {err}", path.display()).into());
            }
        };
        toml::from_str(&contents)
            .map_err(|err| format!("failed to parse config {}: {err}", path.display()).into())
    }

    /// Configured default for granting write access to a worktree's parent git
    /// directory, or `None` to prompt.
    pub fn allow_parent_git(&self) -> Option<bool> {
        self.allow_parent_git
    }

    /// Directories that become the context when the current directory is at or
    /// below one of them, as written in the config (before `~` expansion).
    pub fn context_roots(&self) -> &[String] {
        &self.context_roots
    }

    /// Extra arguments configured for the given agent.
    pub fn preset_args(&self, mode: Mode) -> &[String] {
        match mode {
            Mode::Opencode => &self.opencode.args,
            Mode::Claude => &self.claude.args,
            Mode::Codex => &self.codex.args,
        }
    }
}

/// Path to the config file: `$XDG_CONFIG_HOME/agent-locker/config.toml`, or
/// `~/.config/agent-locker/config.toml` when `XDG_CONFIG_HOME` is unset.
fn config_path() -> Option<PathBuf> {
    let base = match env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("agent-locker").join("config.toml"))
}
