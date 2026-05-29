use std::ffi::OsString;
use std::path::PathBuf;

use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{CommandFactory, Parser};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Opencode,
    Claude,
    Codex,
}

/// Whether to grant write access to a git worktree's parent git directory.
///
/// A worktree's `.git` is a file pointing at the parent repository's shared
/// `.git`, which lives outside the context directory. Writing there (to commit,
/// create branches, etc.) requires an explicit grant because that directory is
/// shared with every other worktree and the main checkout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitAccess {
    /// `--allow-parent-git`: grant access without prompting.
    Allow,
    /// `--no-allow-parent-git`: deny access without prompting.
    Deny,
    /// Neither flag given: defer to the `allow_parent_git` config default,
    /// and prompt when a worktree is detected if that is unset too.
    Ask,
}

/// Color theme for help, usage, and error output.
const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Cyan.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::BrightBlue.on_default())
    .error(AnsiColor::Red.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .invalid(AnsiColor::Yellow.on_default());

const LONG_ABOUT: &str = "\
Run a supported coding agent inside a filesystem sandbox so it can only write \
to a small set of directories.

The sandbox grants write access to the context directory (the current \
directory unless -C is given) and makes the rest of the filesystem read-only \
via Landlock. Each agent preset (opencode, claude, codex) additionally allows \
that agent's own config and cache directories.

The context_roots config key lists directories that become the context \
whenever the agent is launched anywhere beneath them, widening write access \
from just the current directory to the whole root. An explicit -C overrides it.

When the context directory is a git worktree, its parent git directory lives \
outside the worktree and is not writable by default. Pass --allow-parent-git \
to grant write access to it, or --no-allow-parent-git to deny it. With neither \
flag, the allow_parent_git config default applies; if that is unset too, \
agent-locker prompts when it detects a worktree.

Only the built-in agents are supported; arbitrary commands cannot be run.";

const AFTER_HELP: &str = "\
Examples:
  agent-locker claude                   Run claude in the current directory
  agent-locker -C ./project claude      Run claude scoped to ./project
  agent-locker codex --some-flag        Pass extra arguments through to codex

Notes:
  - Supported agents: claude, codex, opencode.
  - The current backend uses Landlock to allow writes only in the context
    directory and a few extra paths; everything else is read-only.";

/// Argument layout as parsed by clap. Converted into [`Cli`] for the rest of
/// the program, which derives the run [`Mode`] from the leading positional.
#[derive(Parser, Debug)]
#[command(
    name = "agent-locker",
    version,
    about = "A sandbox for running coding agents with restricted filesystem access.",
    long_about = LONG_ABOUT,
    after_help = AFTER_HELP,
    styles = STYLES,
)]
struct RawCli {
    /// Use DIR as the main writable project directory
    #[arg(short = 'C', long = "context-dir", value_name = "DIR")]
    context_dir: Option<PathBuf>,

    /// Grant write access to a worktree's parent git directory (no prompt)
    #[arg(long = "allow-parent-git", overrides_with = "no_allow_parent_git")]
    allow_parent_git: bool,

    /// Deny write access to a worktree's parent git directory (no prompt)
    #[arg(long = "no-allow-parent-git", overrides_with = "allow_parent_git")]
    no_allow_parent_git: bool,

    /// Agent to run (claude, codex, opencode), followed by its arguments
    #[arg(
        value_name = "AGENT",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true
    )]
    command_and_args: Vec<OsString>,
}

#[derive(Debug, Clone)]
pub struct Cli {
    pub context_dir: Option<PathBuf>,
    pub mode: Mode,
    pub git_access: GitAccess,
    pub command_and_args: Vec<OsString>,
}

impl Cli {
    /// Parse arguments from the process environment.
    ///
    /// On `--help`/`--version`, a parse error, or an unsupported agent, clap
    /// prints to the appropriate stream and exits the process.
    pub fn parse() -> Self {
        let raw = RawCli::parse();
        match Self::from_raw(raw) {
            Ok(cli) => cli,
            Err(message) => RawCli::command()
                .error(clap::error::ErrorKind::InvalidValue, message)
                .exit(),
        }
    }

    fn from_raw(raw: RawCli) -> Result<Self, String> {
        // `required = true` guarantees at least one value.
        let agent = raw.command_and_args[0].to_str();
        let mode = match agent {
            Some("opencode") => Mode::Opencode,
            Some("claude") => Mode::Claude,
            Some("codex") => Mode::Codex,
            other => {
                let name = other.unwrap_or("<invalid>");
                return Err(format!(
                    "unsupported agent '{name}' (supported agents: claude, codex, opencode)"
                ));
            }
        };

        // `overrides_with` makes the flags last-one-wins, so at most one is
        // set here; absence of both means prompt on detection.
        let git_access = if raw.allow_parent_git {
            GitAccess::Allow
        } else if raw.no_allow_parent_git {
            GitAccess::Deny
        } else {
            GitAccess::Ask
        };

        // The leading keyword selects the agent and is not part of its
        // command line; the remainder is passed through.
        Ok(Cli {
            context_dir: raw.context_dir,
            mode,
            git_access,
            command_and_args: raw.command_and_args[1..].to_vec(),
        })
    }
}
