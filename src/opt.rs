use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    #[arg(long)]
    pub file: PathBuf,
    #[arg(short, long, env = "DB_PASSWORD")]
    pub password: String,
}
