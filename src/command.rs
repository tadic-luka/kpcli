use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
struct Wrapper {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(name = "ls")]
    ListDir {
        #[arg(default_value_t = String::from(""))]
        path: String,
    },
}

impl Command {
    pub fn try_parse(input: &str) -> Result<Self, clap::Error> {
        let words = shlex::split(input).unwrap_or_else(Vec::new);
        let wrapper = Wrapper::try_parse_from([String::from("")].into_iter().chain(words))?;
        Ok(wrapper.cmd)
    }
}
