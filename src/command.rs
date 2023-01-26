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
    #[command(name = "cd")]
    ChangeDir {
        #[arg(default_value_t = String::from(""))]
        path: String,
    },
    /// Show an entry
    #[command(name = "show")]
    Show {
        /// Show hidden values
        #[arg(short = 's')]
        show_hidden: bool,

        entry: String,
    },
    /// Copy passwort to clipboard using OSC52
    /// ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cp")]
    CopyPassword { entry: String },
}

impl Command {
    pub fn try_parse(input: &str) -> Result<Self, clap::Error> {
        let words = shlex::split(input).unwrap_or_else(Vec::new);
        let wrapper = Wrapper::try_parse_from([String::from("")].into_iter().chain(words))?;
        Ok(wrapper.cmd)
    }
}
