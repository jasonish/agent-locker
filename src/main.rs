mod backend;
mod cli;
mod config;
mod git;
mod policy;

use std::io::IsTerminal;
use std::process;

use policy::Policy;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() {
    if let Err(err) = real_main() {
        eprintln!("agent-locker: {err}");
        process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = cli::Cli::parse();
    let policy = Policy::from_cli(cli)?;

    eprint!("{}", policy.render_banner(std::io::stderr().is_terminal()));

    backend::exec(&policy)
}
