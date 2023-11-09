use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;

use clap::CommandFactory;
use fst::{automaton::Str, Automaton, IntoStreamer};
use rustyline::{
    completion::Completer, highlight::Highlighter, hint::Hinter, validate::Validator, Helper,
};

use crate::executor::Command;

pub struct PasswordInput;

pub struct EditorHelper {
    cmd_trie: fst::Set<Vec<u8>>,
    cmds: HashMap<String, clap::Command>,
    cmd_flags_to_arg: HashMap<String, HashMap<String, clap::Arg>>,
}

impl EditorHelper {
    pub fn new() -> Self {
        let cmd = Command::command();
        let mut cmds: Vec<String> = cmd
            .get_subcommands()
            .map(clap::Command::get_name)
            .map(String::from)
            .collect();
        cmds.sort();
        let cmd_trie = fst::Set::from_iter(&cmds).unwrap();
        let cmds = cmds
            .into_iter()
            .map(|subcmd| (subcmd.clone(), cmd.find_subcommand(subcmd).unwrap().clone()))
            .collect();

        let mut cmd_flags_to_arg = HashMap::new();
        for subcmd in cmd.get_subcommands() {
            let mut flags_to_arg = HashMap::new();
            for arg in subcmd.get_arguments() {
                if let Some(long) = arg.get_long() {
                    flags_to_arg.insert(long.to_string(), arg.clone());
                }
                if let Some(short) = arg.get_short() {
                    flags_to_arg.insert(short.to_string(), arg.clone());
                }
            }
            cmd_flags_to_arg.insert(subcmd.get_name().to_string(), flags_to_arg);
        }
        Self {
            cmd_trie,
            cmds,
            cmd_flags_to_arg,
        }
    }

    fn find_cmds_starting_with(&self, word: &str) -> Vec<String> {
        self.cmd_trie
            .search(Str::new(word).starts_with())
            .into_stream()
            .into_strs()
            .unwrap()
    }

    fn find_non_positional_args<'a>(
        &'a self,
        cmd: &str,
        prefix: &str,
        is_short: bool,
        ignore_flags: HashSet<&clap::Id>,
    ) -> Vec<String> {
        let cmd = if let Some(cmd) = self.cmds.get(cmd) {
            cmd
        } else {
            return Vec::new();
        };

        let iter = cmd
            .get_arguments()
            .filter(|arg| !arg.is_positional() && !ignore_flags.contains(arg.get_id()));
        if is_short && prefix.is_empty() {
            iter.flat_map(|val| {
                [
                    val.get_short().map(String::from),
                    val.get_long().map(|val| format!("-{}", val)),
                ]
                .into_iter()
                .filter_map(std::convert::identity)
            })
            .collect()
        } else if is_short {
            Vec::new()
        } else {
            iter.filter_map(|arg| arg.get_long())
                .filter_map(|val| val.strip_prefix(prefix))
                .map(String::from)
                .collect()
        }
    }
}

impl Highlighter for PasswordInput {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Owned("*".repeat(line.len()))
    }

    fn highlight_char(&self, _line: &str, _pos: usize) -> bool {
        true
    }
}

impl Validator for PasswordInput {}

impl Hinter for PasswordInput {
    type Hint = String;
}

impl Completer for PasswordInput {
    type Candidate = String;
}

impl Helper for PasswordInput {}

impl Highlighter for EditorHelper {}

impl Validator for EditorHelper {
    fn validate(
        &self,
        ctx: &mut rustyline::validate::ValidationContext,
    ) -> rustyline::Result<rustyline::validate::ValidationResult> {
        if let Err(err) = Command::try_parse(ctx.input()) {
            return Ok(rustyline::validate::ValidationResult::Invalid(Some(
                format!("\n{}", err.to_string()),
            )));
        }
        Ok(rustyline::validate::ValidationResult::Valid(None))
    }

    fn validate_while_typing(&self) -> bool {
        false
    }
}
impl Hinter for EditorHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &rustyline::Context<'_>) -> Option<Self::Hint> {
        let _ = (line, pos, ctx);
        None
    }
}

impl Completer for EditorHelper {
    type Candidate = String;

    fn complete(
        &self, // FIXME should be `&mut self`
        line: &str,
        pos: usize,
        ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        if pos == 0 {
            // completing all cmds
            return Ok((0, self.cmds.keys().map(String::from).collect()));
        } else if pos != line.len() {
            // won't complete if not at last position in line
            return Ok((0, Vec::new()));
        }
        let words = shlex::split(line).unwrap_or_else(Vec::new);
        if words.len() == 1 {
            let word = &words[0];
            if pos > word.len() {
                // TODO: autocomplete positional argument only if needed
                // don't autocomplete if user is moved from typing command
                return Ok((0, Vec::new()));
            }
            return Ok((0, self.find_cmds_starting_with(word)));
        }
        let cmd = &words[0];
        let last = &words[words.len() - 1];

        // autocomplete flag/option
        // if user input starts with "-"
        // and current input position is not whitespace
        if last.starts_with("-")
            && line
                .chars()
                .nth(pos - 1)
                .is_some_and(|val| !val.is_whitespace())
        {
            let is_short = !last.starts_with("--");
            let prefix = last.trim_start_matches("-");
            let cmd_flags_to_arg = self.cmd_flags_to_arg.get(cmd);
            let existing_flags: HashSet<&clap::Id> = if words.len() > 2 {
                words[1..words.len() - 1]
                    .into_iter()
                    .map(String::as_str)
                    .map(|val| val.trim_start_matches("-"))
                    .filter_map(|val| {
                        cmd_flags_to_arg.and_then(|flags_to_arg| flags_to_arg.get(val))
                    })
                    .map(|arg| arg.get_id())
                    .collect()
            } else {
                HashSet::new()
            };
            return Ok((
                pos,
                self.find_non_positional_args(cmd, prefix, is_short, existing_flags),
            ));
        }

        let _ = (line, pos, ctx);
        Ok((0, Vec::with_capacity(0)))
    }

    fn update(&self, line: &mut rustyline::line_buffer::LineBuffer, start: usize, elected: &str) {
        eprintln!("Updating line with {}", elected);
        let end = line.pos();
        line.replace(start..end, elected);
    }
}
impl Helper for EditorHelper {}
