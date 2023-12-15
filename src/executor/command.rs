use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(help_template("{tab}{subcommands}"))]
pub enum Command {
    /// List nodes in the group or print entry.
    #[command(name = "ls")]
    ListDir {
        #[arg(default_value_t = String::from(""), value_hint=clap::ValueHint::Other)]
        path: String,
    },
    /// Change current group to given one.
    #[command(name = "cd")]
    ChangeDir {
        // Relative path of group. Must not be entry!
        #[arg(default_value_t = String::from(""), value_hint=clap::ValueHint::Other)]
        path: String,
    },
    /// Show an entry, if it's a group prints nothing.
    #[command(name = "show")]
    Show {
        /// Show hidden values
        #[arg(short = 's')]
        show_hidden: bool,

        /// Show TOTP if exists.
        /// Prints error if it doesn't.
        /// Takes precedence over show_hidden.
        #[arg(long, short)]
        totp: bool,

        /// Relative path to entry.
        #[arg(value_hint=clap::ValueHint::Other)]
        entry: String,
    },
    /// Copy password to clipboard using OSC52
    /// ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cp")]
    CopyPassword {
        /// Relative path to entry.
        #[arg(value_hint=clap::ValueHint::Other)]
        entry: String,
    },

    /// Copy username to clipboard using OSC52
    /// ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cu")]
    CopyUsername {
        /// Relative path to entry.
        #[arg(value_hint=clap::ValueHint::Other)]
        entry: String,
    },

    /// Copy URL (www) to clipboard using OSC52
    /// ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cw")]
    CopyURL {
        /// Relative path to entry.
        #[arg(value_hint=clap::ValueHint::Other)]
        entry: String,
    },

    /// Clear clipboard using OSC52 ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cx")]
    ClearClipboard,

    /// Open database with given file path and password.
    /// Not allowed if database is another already opened.
    #[command(name = "open")]
    OpenDB {
        // Absolute or relative path to database
        #[arg(value_hint=clap::ValueHint::FilePath)]
        path: PathBuf,
        // Password for given database
        password: String,
    },

    /// Close currently opened database.
    #[command(name = "close")]
    CloseDB,
}

impl Command {
    pub fn try_parse(input: &str) -> Result<Self, clap::Error> {
        let words = shlex::split(input).unwrap_or_else(Vec::new);
        Self::try_parse_from([String::new()].into_iter().chain(words))
    }
}
