use crate::executor::Command;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Opts {
    #[arg(long)]
    pub db_file: Option<PathBuf>,

    #[arg(short, long, env = "DB_PASSWORD")]
    pub password: Option<String>,

    /// Optionally run single command and exit (no interactive session).
    #[command(subcommand)]
    pub command: Option<Command>,
}
