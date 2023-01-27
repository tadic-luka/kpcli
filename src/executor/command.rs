use clap::Parser;

#[derive(Debug, Parser)]
#[command(help_template("{tab}{subcommands}"))]
pub enum Command {
    /// List nodes in the group or print entry.
    #[command(name = "ls")]
    ListDir {
        #[arg(default_value_t = String::from(""))]
        path: String,
    },
    /// Change current group to given one.
    #[command(name = "cd")]
    ChangeDir {
        // Relative path of group. Must not be entry!
        #[arg(default_value_t = String::from(""))]
        path: String,
    },
    /// Show an entry, if it's a group prints nothing.
    #[command(name = "show")]
    Show {
        /// Show hidden values
        #[arg(short = 's')]
        show_hidden: bool,

        /// Relative path to entry.
        entry: String,
    },
    /// Copy password to clipboard using OSC52
    /// ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cp")]
    CopyPassword {
        /// Relative path to entry.
        entry: String,
    },

    /// Copy username to clipboard using OSC52
    /// ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cu")]
    CopyUsername {
        /// Relative path to entry.
        entry: String,
    },

    /// Copy URL (www) to clipboard using OSC52
    /// ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cw")]
    CopyURL {
        /// Relative path to entry.
        entry: String,
    },

    /// Clear clipboard using OSC52 ANSI escape sequence.
    /// Not all terminals support this!
    #[command(name = "cx")]
    ClearClipboard,
}

impl Command {
    pub fn try_parse(input: &str) -> Result<Self, clap::Error> {
        let words = shlex::split(input).unwrap_or_else(Vec::new);
        Self::try_parse_from([String::new()].into_iter().chain(words))
    }
}
