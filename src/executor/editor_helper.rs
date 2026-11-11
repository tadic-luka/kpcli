use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;

use clap::CommandFactory;
use fst::{automaton::Str, Automaton, IntoStreamer};
use keepass::db::NodeRef;
use keepass::Database;
use rustyline::{
    completion::{escape, extract_word, unescape, Completer, Quote},
    highlight::Highlighter,
    hint::Hinter,
    validate::Validator,
    Helper,
};
use uuid::Uuid;

use crate::executor::get_all_prefixes_under_group;
use crate::executor::Command;

pub struct PasswordInput;

pub struct EditorHelper {
    cmd_trie: fst::Set<Vec<u8>>,
    cmds: HashMap<String, clap::Command>,
    cmd_flags_to_arg: HashMap<String, HashMap<String, clap::Arg>>,
    dir_stack: Vec<Uuid>,
    db_entries: HashMap<Uuid, fst::Set<Vec<u8>>>,
    db_root: Uuid,
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
            dir_stack: Vec::new(),
            db_entries: HashMap::new(),
            db_root: Uuid::nil(),
        }
    }

    pub fn create_db_entries(&mut self, db: &Database) {
        self.db_entries.clear();
        self.db_root = db.root.uuid;
        for node in &db.root {
            if let NodeRef::Group(g) = node {
                let all_entries = get_all_prefixes_under_group(g);
                let all_entries_trie = fst::Set::from_iter(&all_entries).unwrap();
                self.db_entries.insert(g.uuid, all_entries_trie);
            }
        }
    }

    pub fn clear_db(&mut self) {
        self.dir_stack.clear();
        self.db_entries.clear();
    }

    pub fn set_dir_stack(&mut self, dir_stack: Vec<Uuid>) {
        self.dir_stack = dir_stack;
    }

    fn find_cmds_starting_with(&self, word: &str) -> Vec<String> {
        self.cmd_trie
            .search(Str::new(word).starts_with())
            .into_stream()
            .into_strs()
            .unwrap()
    }

    fn find_non_positional_args(
        &self,
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
                .flatten()
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

    fn find_positional_args(&self, cmd: &str, prefix: &str) -> Vec<String> {
        let cmd = if let Some(cmd) = self.cmds.get(cmd) {
            cmd
        } else {
            return Vec::new();
        };
        let mut result = Vec::new();
        if cmd
            .get_arguments()
            .any(|arg| arg.is_positional() && arg.get_value_hint() == clap::ValueHint::Other)
        {
            // this is entry in keepass database
            // get database entries here
            let curr_dir = self.dir_stack.last().unwrap_or(&self.db_root);
            if let Some(trie) = self.db_entries.get(curr_dir) {
                let matches: Vec<String> = trie
                    .search(Str::new(prefix).starts_with())
                    .into_stream()
                    .into_strs()
                    .unwrap_or_default();
                for item in matches {
                    let suffix = &item[prefix.len()..];
                    if suffix.is_empty() {
                        continue;
                    }
                    let next_component = match suffix.find('/') {
                        Some(idx) => &item[..prefix.len() + idx + 1],
                        None => item.as_str(),
                    };

                    // 'cd' strictly accepts groups (which end with '/')
                    if cmd.get_name() == "cd" && !next_component.ends_with('/') {
                        continue;
                    }

                    result.push(escape(
                        next_component.to_string(),
                        ESC_CHAR,
                        ESCAPED_CHARS,
                        Quote::None,
                    ));
                }
            }
        }
        result.sort();
        result.dedup();
        result
    }

    /// Completion logic behind [`Completer::complete`], without rustyline's
    /// `Context`, so tests can call it directly.
    fn complete_at(&self, line: &str, pos: usize) -> (usize, Vec<String>) {
        if pos == 0 {
            // completing all cmds
            return (0, self.cmds.keys().map(String::from).collect());
        } else if pos != line.len() {
            // won't complete if not at last position in line
            return (0, Vec::new());
        }

        let cmd = match line.split_whitespace().next() {
            Some(c) => c,
            None => return (0, Vec::new()),
        };

        if pos <= cmd.len() {
            return (0, self.find_cmds_starting_with(cmd));
        }

        let (arg_start, raw_arg) = extract_word(line, pos, ESC_CHAR, WORD_BREAKS);

        // autocomplete flag/option
        // if user input starts with "-"
        // and current input position is not whitespace
        if raw_arg.starts_with('-') && !line[..pos].ends_with(char::is_whitespace) {
            let is_short = !raw_arg.starts_with("--");
            let prefix = raw_arg.trim_start_matches('-');
            let cmd_flags_to_arg = self.cmd_flags_to_arg.get(cmd);
            let existing_flags: HashSet<&clap::Id> = if let Some(flags_to_arg) = cmd_flags_to_arg {
                shlex::split(&line[..arg_start])
                    .unwrap_or_default()
                    .iter()
                    .map(String::as_str)
                    .map(|val| val.trim_start_matches('-'))
                    .filter_map(|val| flags_to_arg.get(val))
                    .map(|arg| arg.get_id())
                    .collect()
            } else {
                HashSet::new()
            };
            return (
                pos,
                self.find_non_positional_args(cmd, prefix, is_short, existing_flags),
            );
        }

        // positional arg
        let unescaped_prefix = unescape(raw_arg, ESC_CHAR);
        let res = self.find_positional_args(cmd, &unescaped_prefix);
        (arg_start, res)
    }
}

/// Escape character used in completions; `shlex::split` (used by
/// `Command::try_parse`) treats `\x` as a literal `x` in an unquoted word.
const ESC_CHAR: Option<char> = Some('\\');

/// Characters separating arguments when locating the word under the cursor.
const WORD_BREAKS: &[u8] = b" \t";

/// Characters that `shlex::split` treats specially in an unquoted word.
/// Each is backslash-escaped in completions so it parses back unchanged.
const ESCAPED_CHARS: &[u8] = b" \t'\"\\#";

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
                format!("\n{}", err),
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
        _ctx: &rustyline::Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Self::Candidate>)> {
        Ok(self.complete_at(line, pos))
    }

    fn update(&self, line: &mut rustyline::line_buffer::LineBuffer, start: usize, elected: &str) {
        let end = line.pos();
        line.replace(start..end, elected);
    }
}
impl Helper for EditorHelper {}

#[cfg(test)]
mod tests {
    use super::*;

    fn esc(s: &str) -> String {
        escape(s.to_string(), ESC_CHAR, ESCAPED_CHARS, Quote::None)
    }

    fn arg_start(line: &str) -> usize {
        extract_word(line, line.len(), ESC_CHAR, WORD_BREAKS).0
    }

    #[test]
    fn test_arg_start() {
        assert_eq!(arg_start("cd "), 3);
        assert_eq!(arg_start("cd General"), 3);
        assert_eq!(arg_start("cd General\\ Info"), 3);
        assert_eq!(arg_start("cd General\\ Info/Sub"), 3);
        assert_eq!(arg_start("show -s Entry"), 8);
        assert_eq!(arg_start("show\tEntry"), 5);
    }

    #[test]
    fn test_find_positional_args_completion() {
        let mut helper = EditorHelper::new();
        let entries = vec![
            "General/".to_string(),
            "General/Finance/".to_string(),
            "General/Finance/Bank Account".to_string(),
            "General/Notes".to_string(),
            "Personal Docs/".to_string(),
            "Personal Docs/ID Card".to_string(),
        ];
        let trie = fst::Set::from_iter(&entries).unwrap();
        let root_uuid = Uuid::new_v4();
        helper.db_root = root_uuid;
        helper.db_entries.insert(root_uuid, trie);

        // cd at root: should only return groups, truncated to next component, spaces escaped
        let cd_root = helper.find_positional_args("cd", "");
        assert_eq!(cd_root, vec!["General/", "Personal\\ Docs/"]);

        // show at root: returns both groups and top-level entries (all are in groups here)
        let show_root = helper.find_positional_args("show", "");
        assert_eq!(show_root, vec!["General/", "Personal\\ Docs/"]);

        // cd inside General/: only returns groups under General/
        let cd_gen = helper.find_positional_args("cd", "General/");
        assert_eq!(cd_gen, vec!["General/Finance/"]);

        // show inside General/: returns sub-groups and entries
        let show_gen = helper.find_positional_args("show", "General/");
        assert_eq!(show_gen, vec!["General/Finance/", "General/Notes"]);

        // show inside General/Finance/: completes nested entry with space escaped
        let show_fin = helper.find_positional_args("show", "General/Finance/");
        assert_eq!(show_fin, vec!["General/Finance/Bank\\ Account"]);

        // show inside Personal Docs/: completes nested entry with spaces escaped
        let show_pers = helper.find_positional_args("show", "Personal Docs/");
        assert_eq!(show_pers, vec!["Personal\\ Docs/ID\\ Card"]);
    }

    #[test]
    fn test_escape_round_trips_through_command_parsing() {
        let names = [
            "plain",
            "with space",
            "Bob's Bank",
            "say \"hi\"",
            "back\\slash",
            "#hashtag",
            "mid#hash",
            "tab\there",
            " padded ",
            "trailing\\",
        ];
        for name in names {
            let escaped = esc(name);
            assert_eq!(unescape(&escaped, ESC_CHAR), name, "unescape({escaped:?})");
            let words = shlex::split(&format!("show {escaped}"));
            assert_eq!(
                words,
                Some(vec!["show".to_string(), name.to_string()]),
                "shlex::split of {escaped:?}"
            );
            // escaped spaces/tabs must not split the argument for completion
            let line = format!("show {escaped}");
            assert_eq!(arg_start(&line), 5, "{line:?}");
        }
        assert_eq!(unescape("Personal\\", ESC_CHAR), "Personal");
    }

    #[test]
    fn test_complete_special_chars() {
        let mut helper = EditorHelper::new();
        let entries = vec![
            "Bob's \"Bank\"/".to_string(),
            "Bob's \"Bank\"/#1 acct".to_string(),
        ];
        let trie = fst::Set::from_iter(&entries).unwrap();
        let root_uuid = Uuid::new_v4();
        helper.db_root = root_uuid;
        helper.db_entries.insert(root_uuid, trie);

        let typed = r#"Bob\'s\ \"Bank\"/"#;
        let res = helper.find_positional_args("show", &unescape(typed, ESC_CHAR));
        assert_eq!(res, vec![r#"Bob\'s\ \"Bank\"/\#1\ acct"#]);
        let cmd = Command::try_parse(&format!("show {}", res[0])).unwrap();
        match cmd {
            Command::Show { entry, .. } => assert_eq!(entry, "Bob's \"Bank\"/#1 acct"),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Helper with a small completion index for the root group.
    fn helper_with_entries() -> EditorHelper {
        let mut helper = EditorHelper::new();
        let entries = vec![
            "General/".to_string(),
            "General/Finance/".to_string(),
            "General/Notes".to_string(),
            "Personal/".to_string(),
        ];
        let trie = fst::Set::from_iter(&entries).unwrap();
        let root_uuid = Uuid::new_v4();
        helper.db_root = root_uuid;
        helper.db_entries.insert(root_uuid, trie);
        helper
    }

    /// `complete_at` with the cursor at the end of `line`.
    fn complete_end(helper: &EditorHelper, line: &str) -> (usize, Vec<String>) {
        helper.complete_at(line, line.len())
    }

    #[test]
    fn test_complete_all_commands_on_empty_line() {
        let helper = EditorHelper::new();
        let (start, mut cmds) = helper.complete_at("", 0);
        assert_eq!(start, 0);
        // order comes from a HashMap today, so sort before comparing
        cmds.sort();
        assert_eq!(
            cmds,
            vec!["cd", "close", "cp", "cu", "cw", "cx", "ls", "open", "show"]
        );
    }

    #[test]
    fn test_complete_command_name() {
        let helper = EditorHelper::new();
        assert_eq!(
            complete_end(&helper, "c"),
            (
                0,
                vec!["cd", "close", "cp", "cu", "cw", "cx"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
        assert_eq!(complete_end(&helper, "sh"), (0, vec!["show".to_string()]));
        assert_eq!(complete_end(&helper, "cd"), (0, vec!["cd".to_string()]));
        assert_eq!(complete_end(&helper, "xyz"), (0, Vec::new()));
    }

    #[test]
    fn test_complete_nothing_when_cursor_not_at_end_or_blank_line() {
        let helper = helper_with_entries();
        assert_eq!(helper.complete_at("show Gen", 2), (0, Vec::new()));
        assert_eq!(helper.complete_at("show Gen", 6), (0, Vec::new()));
        assert_eq!(complete_end(&helper, "   "), (0, Vec::new()));
    }

    #[test]
    fn test_complete_flags() {
        let helper = EditorHelper::new();
        // `-` alone: short letters, plus long names with one more dash
        assert_eq!(
            complete_end(&helper, "show -"),
            (
                6,
                vec!["s", "t", "-totp"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
        // a short flag is already complete, nothing to add
        assert_eq!(complete_end(&helper, "show -s"), (7, Vec::new()));
        // long flags complete with the rest of the name (a suffix)
        assert_eq!(
            complete_end(&helper, "show --t"),
            (8, vec!["otp".to_string()])
        );
        assert_eq!(
            complete_end(&helper, "show --"),
            (7, vec!["totp".to_string()])
        );
        assert_eq!(complete_end(&helper, "show --x"), (8, Vec::new()));
        // commands without flags
        assert_eq!(complete_end(&helper, "cd -"), (4, Vec::new()));
        assert_eq!(complete_end(&helper, "nope -"), (6, Vec::new()));
    }

    #[test]
    fn test_complete_flags_skips_used_ones() {
        let helper = EditorHelper::new();
        assert_eq!(
            complete_end(&helper, "show -t -"),
            (9, vec!["s".to_string()])
        );
        assert_eq!(
            complete_end(&helper, "show --totp -"),
            (13, vec!["s".to_string()])
        );
        assert_eq!(complete_end(&helper, "show --totp --"), (14, Vec::new()));
        assert_eq!(complete_end(&helper, "show -s -t -"), (12, Vec::new()));
    }

    #[test]
    fn test_complete_positional() {
        let helper = helper_with_entries();
        assert_eq!(
            complete_end(&helper, "show "),
            (5, vec!["General/".to_string(), "Personal/".to_string()])
        );
        assert_eq!(
            complete_end(&helper, "show Gen"),
            (5, vec!["General/".to_string()])
        );
        assert_eq!(
            complete_end(&helper, "show General/"),
            (
                5,
                vec!["General/Finance/".to_string(), "General/Notes".to_string()]
            )
        );
        assert_eq!(
            complete_end(&helper, "cd General/"),
            (3, vec!["General/Finance/".to_string()])
        );
        // positional after a flag
        assert_eq!(
            complete_end(&helper, "show -s General/N"),
            (8, vec!["General/Notes".to_string()])
        );
        // a fully typed name has nothing left to complete
        assert_eq!(complete_end(&helper, "show General/Notes"), (5, Vec::new()));
        // commands whose positional arg is not a db path
        assert_eq!(complete_end(&helper, "open Gen"), (5, Vec::new()));
        assert_eq!(complete_end(&helper, "nope Gen"), (5, Vec::new()));
    }

    #[test]
    fn test_complete_positional_in_subgroup() {
        let mut helper = helper_with_entries();
        let general_uuid = Uuid::new_v4();
        let entries = vec!["Finance/".to_string(), "Notes".to_string()];
        helper
            .db_entries
            .insert(general_uuid, fst::Set::from_iter(&entries).unwrap());
        helper.set_dir_stack(vec![general_uuid]);
        assert_eq!(
            complete_end(&helper, "show "),
            (5, vec!["Finance/".to_string(), "Notes".to_string()])
        );

        // no index for the current group: no completions, no panic
        helper.set_dir_stack(vec![Uuid::new_v4()]);
        assert_eq!(complete_end(&helper, "show "), (5, Vec::new()));
    }

    #[test]
    #[ignore = "known bug: completing an empty line returns commands in HashMap order"]
    fn test_complete_empty_line_is_sorted() {
        let helper = EditorHelper::new();
        let (_, cmds) = helper.complete_at("", 0);
        let mut sorted = cmds.clone();
        sorted.sort();
        assert_eq!(cmds, sorted);
    }

    #[test]
    fn test_complete_flags_after_non_ascii() {
        let helper = EditorHelper::new();
        let line = "show é -";
        assert_eq!(
            complete_end(&helper, line),
            (
                line.len(),
                vec!["s", "t", "-totp"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            )
        );
    }

    #[test]
    #[ignore = "known bug: command-name completion assumes the command starts at byte 0"]
    fn test_complete_command_name_after_leading_whitespace() {
        let helper = EditorHelper::new();
        assert_eq!(complete_end(&helper, "  sh"), (2, vec!["show".to_string()]));
    }

    #[test]
    fn test_complete_escaped_space_after_dash_is_not_a_flag() {
        // `-\ ` is a path starting with "- ", not a flag
        let helper = EditorHelper::new();
        assert_eq!(complete_end(&helper, "show -\\ "), (5, Vec::new()));
    }

    fn find_flags(helper: &EditorHelper, cmd: &str, prefix: &str, is_short: bool) -> Vec<String> {
        helper.find_non_positional_args(cmd, prefix, is_short, HashSet::new())
    }

    #[test]
    fn test_find_non_positional_args() {
        let helper = EditorHelper::new();
        assert_eq!(
            find_flags(&helper, "show", "", true),
            vec!["s", "t", "-totp"]
        );
        assert_eq!(find_flags(&helper, "show", "s", true), Vec::<String>::new());
        assert_eq!(find_flags(&helper, "show", "", false), vec!["totp"]);
        assert_eq!(find_flags(&helper, "show", "to", false), vec!["tp"]);
        assert_eq!(
            find_flags(&helper, "show", "x", false),
            Vec::<String>::new()
        );
        // positional args (`entry`) are never offered
        assert!(!find_flags(&helper, "show", "", true).contains(&"entry".to_string()));
        // commands without flags, and unknown commands
        assert_eq!(find_flags(&helper, "cd", "", true), Vec::<String>::new());
        assert_eq!(find_flags(&helper, "nope", "", true), Vec::<String>::new());

        // flags already on the line are skipped
        let show = helper.cmds.get("show").unwrap();
        let totp_id = show
            .get_arguments()
            .find(|arg| arg.get_long() == Some("totp"))
            .unwrap()
            .get_id();
        let used = HashSet::from([totp_id]);
        assert_eq!(
            helper.find_non_positional_args("show", "", true, used.clone()),
            vec!["s"]
        );
        assert_eq!(
            helper.find_non_positional_args("show", "", false, used),
            Vec::<String>::new()
        );
    }
}
