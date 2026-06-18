# Agent Locker

A sandbox for running coding agents with restricted filesystem access. The
whole filesystem is made **read-only** via
[Landlock](https://docs.kernel.org/userspace-api/landlock.html); only a small,
explicit set of paths is writable.

agent-locker itself only ever launches one of the built-in agents (`claude`,
`codex`, `opencode`) — you cannot ask it to run an arbitrary top-level command.
This does **not** stop a launched agent from spawning other processes; see
[Threat model](#threat-model) for what the sandbox does and does not protect.

Requires Linux 5.13+ with Landlock enabled, and currently x86_64 only.

## Threat model

agent-locker constrains **filesystem writes** and nothing else. It is an
*integrity* boundary — it stops unwanted modifications — not a *confidentiality*
or *network* boundary. Understand the difference before relying on it,
especially if you opt into flags like `--dangerously-skip-permissions` (see
[Configuration](#configuration)), which lean on this sandbox as the safety net.

**What it protects:** files and directories outside the writable set cannot be
modified, created, deleted, or have their metadata changed. An agent — or
anything it runs — cannot overwrite your home directory, system files, other
projects, or (by default) a git worktree's shared parent git directory.

**What it does *not* protect:**

- **Reading.** The entire filesystem stays readable. Secrets such as `~/.ssh`,
  `~/.aws/credentials`, API tokens, and other projects' source are all readable
  by the agent.
- **Network.** The Landlock backend restricts only the filesystem; outbound
  network access is unrestricted. Anything readable can be exfiltrated.
- **Process execution.** The whole filesystem remains executable. A launched
  agent can spawn arbitrary subprocesses and run any binary on the system. "Only
  the built-in agents are supported" refers solely to what *agent-locker*
  launches, not to what the agent does afterward.

`/dev/tty` is writable because interactive agents need it. agent-locker
installs a small seccomp filter that blocks the `TIOCSTI` ioctl, so the agent
cannot inject keystrokes into the controlling terminal to run commands in the
launching shell after it exits — independent of kernel version (the Linux 6.2
`TIOCSTI` hardening covers only newer kernels). Other terminal ioctls are
unaffected.

If you need confidentiality, network isolation, or execution confinement, run
the agent in a VM or container with no network and no access to your secrets;
agent-locker alone does not provide them.

## Usage

```
agent-locker [-C DIR] <agent> [args...]
```

- `-C, --context-dir DIR` — the main writable project directory (defaults to
  the current directory).
- `--allow-parent-git` / `--no-allow-parent-git` — grant or deny write access
  to a git worktree's parent git directory without prompting (see
  [Git worktrees](#git-worktrees)).
- `<agent>` must be one of `claude`, `codex`, or `opencode`. Any following
  arguments are passed through to the agent.

```sh
agent-locker claude               # claude in the current directory
agent-locker -C ./project claude  # claude scoped to ./project
agent-locker codex --some-flag    # pass extra arguments through to codex
```

## What's writable

Every invocation grants write access to:

- the **context directory**,
- `/tmp`,
- `/dev/null` and `/dev/tty` — the only device nodes any agent needs to
  *write* (verified via `strace`). Reads elsewhere (e.g. `/dev/urandom`) still
  work because the rest of the filesystem remains readable.

Everything else — including the home directory, `/dev`, and `/run/user` — is
read-only unless listed below.

### Agent-specific writable paths

Each agent additionally allows its own config/cache directories:

| Agent      | Program    | Extra writable paths                                          |
|------------|------------|---------------------------------------------------------------|
| `claude`   | `claude`   | `~/.claude` (see below)                                       |
| `codex`    | `codex`    | `~/.codex`                                                     |
| `opencode` | `opencode` | `~/.opencode`, `~/.local/share/opencode`, `~/.cache/opencode` |

claude normally stores its main config in `~/.claude.json`, but it writes that
file atomically — to a temp file in the same directory, then `rename()`d over
the target — which needs permission to create and remove files in the file's
**parent** directory. Granting that on `$HOME` would make the whole home
directory writable, defeating the sandbox, and a file-level Landlock rule on
`~/.claude.json` cannot authorize the rename. So for the `claude` preset,
agent-locker sets `CLAUDE_CONFIG_DIR=~/.claude`, which relocates the config to
`~/.claude/.claude.json` — inside the already-writable config directory, where
the atomic write succeeds. On first sandboxed run an existing `~/.claude.json`
is copied in so history, onboarding, and MCP approvals carry over.

Because of this, a sandboxed claude reads and writes `~/.claude/.claude.json`
while a claude launched normally (outside agent-locker) still uses
`~/.claude.json`; the two diverge after the initial copy. To keep a single
config across both, set `CLAUDE_CONFIG_DIR=~/.claude` in your own environment so
the normal claude uses the same relocated file.

Agents run in their **default mode** — agent-locker does not force flags like
`--dangerously-skip-permissions`. Use the config file to opt in.

## Git worktrees

In a [git worktree](https://git-scm.com/docs/git-worktree), the `.git` entry is
a file pointing at the parent repository's git directory, which lives outside
the worktree (e.g. working in `…/suricata/review`, a worktree of
`…/suricata/main`, the parent git directory is `…/suricata/main/.git`). Writing
there — to commit, create branches, stash, etc. — needs an explicit grant,
because that directory is shared with the main checkout and every other
worktree.

agent-locker does **not** grant it by default. When it detects that the context
directory is a worktree, it:

- grants write access if `--allow-parent-git` was passed,
- leaves it read-only if `--no-allow-parent-git` was passed,
- otherwise applies the `allow_parent_git` config default (see
  [Configuration](#configuration)) if set,
- otherwise **prompts** you (and leaves it read-only if there is no terminal to
  prompt, e.g. when run non-interactively).

The command-line flags always override the config default.

Ordinary (non-worktree) repositories are unaffected: their `.git` lives inside
the context directory and is writable as part of it.

## Context roots

Sometimes you want a wider writable area than the current directory — for
example, a development tree where you move between sibling checkouts and expect
the agent to write across all of them. The `context_roots` config key lists
such directories:

```toml
context_roots = ["~/oisf/dev"]
```

When you launch an agent **without** `-C` and the current directory is at or
below a configured root, that root becomes the context (the main writable
project directory) instead of the current directory. So running anywhere under
`~/oisf/dev` — say `~/oisf/dev/suricata/src` — scopes the sandbox to all of
`~/oisf/dev`.

- The deepest (most specific) matching root wins, so you can list both
  `~/oisf` and `~/oisf/dev` and the latter applies when you are beneath it.
- An explicit `-C`/`--context-dir` always overrides context roots.
- Matching is by path component, so `~/oisf/dev` does not match a sibling like
  `~/oisf/development`.
- Because the root becomes the context, git worktree detection (and the
  `allow_parent_git` prompt) applies to the root, not the current directory.

## Configuration

Optional config file at `$XDG_CONFIG_HOME/agent-locker/config.toml`, falling
back to `~/.config/agent-locker/config.toml` when `XDG_CONFIG_HOME` is unset.

The top-level `allow_parent_git` key sets the default for a git worktree's
parent git directory (see [Git worktrees](#git-worktrees)), so you are never
prompted; `--allow-parent-git` / `--no-allow-parent-git` override it.

The top-level `context_roots` key lists directories that become the context
whenever the agent is launched at or beneath them (see
[Context roots](#context-roots)).

Each preset section may supply `args`, which are prepended to the preset's
command line, before any arguments you pass on the command line. A missing
config file is fine. Unknown keys are ignored so a config written for a
different agent-locker version still loads; only a config that is not valid
TOML is an error.

### Exhaustive example

```toml
# Default for granting write access to a git worktree's parent git directory.
# Omit to be prompted on detection; the --allow-parent-git / --no-allow-parent-git
# flags override this.
allow_parent_git = false

# Directories that become the context (the main writable project directory)
# whenever the agent is launched at or beneath them. See "Context roots" below.
context_roots = ["~/projects/evebox"]

# Arguments are prepended to the preset's command line, before any arguments
# passed on the command line. Each section is optional; omit a section to run
# that preset with no extra arguments.

[claude]
# Skip claude's interactive permission prompts.
args = ["--dangerously-skip-permissions"]

[codex]
# Bypass codex's own approval/sandbox prompts.
args = ["--dangerously-bypass-approvals-and-sandbox"]

[opencode]
# opencode takes no special arguments by default; add your own here.
args = []
```
