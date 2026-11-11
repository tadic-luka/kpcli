mod command;
mod editor_helper;
mod state;

use std::fs::File;

pub use command::Command;
pub use editor_helper::EditorHelper;
pub use editor_helper::PasswordInput;
use keepass::DatabaseKey;
use keepass::{
    db::{Entry, NodeRef, Value},
    Database,
};
pub use state::get_all_prefixes_under_group;
use state::{Db, State};
use totp_rs::TOTP;

pub struct Executor {
    state: State,
}

impl Executor {
    pub fn new(db: Option<Database>) -> Self {
        Self {
            state: State::new(db),
        }
    }

    pub fn get_current_group_name(&self) -> Option<&str> {
        self.state
            .db
            .as_ref()
            .map(|db| db.get_current_group().name.as_ref())
    }

    pub fn get_db(&self) -> Option<&Database> {
        self.state.db.as_ref().map(|db| &db.db)
    }

    fn db(&self) -> Result<&Db, String> {
        self.state
            .db
            .as_ref()
            .ok_or_else(|| "Database not opened".to_string())
    }

    fn db_mut(&mut self) -> Result<&mut Db, String> {
        self.state
            .db
            .as_mut()
            .ok_or_else(|| "Database not opened".to_string())
    }

    /// The group or entry at `path`.
    fn node(&self, path: &str) -> Result<NodeRef<'_>, String> {
        self.db()?
            .get_node(path)
            .ok_or_else(|| format!("{} does not exist!", path))
    }

    /// The entry at `path`; a group there is an error.
    fn entry(&self, path: &str) -> Result<&Entry, String> {
        match self.db()?.get_node(path) {
            Some(NodeRef::Entry(e)) => Ok(e),
            Some(NodeRef::Group(_)) | None => {
                Err(format!("{} is not an entry or doesn't exist!", path))
            }
        }
    }

    pub fn execute(
        &mut self,
        command: Command,
        editor_helper: &mut EditorHelper,
    ) -> Result<(), String> {
        match command {
            Command::ListDir { path } => self.node(&path).map(list_node),
            Command::ChangeDir { path } => {
                let db = self.db_mut()?;
                if !db.change_current_group(&path) {
                    return Err(format!("{} is not a group or doesn't exist!", path));
                }
                editor_helper.set_dir_stack(db.dir_stack.clone());
                Ok(())
            }
            Command::Show {
                show_hidden,
                entry,
                totp,
            } => self
                .node(&entry)
                .map(|node| print_node(node, show_hidden, totp)),
            Command::CopyPassword { entry } => {
                self.entry(&entry).map(|e| copy_entry_field(e, "Password"))
            }
            Command::CopyUsername { entry } => {
                self.entry(&entry).map(|e| copy_entry_field(e, "UserName"))
            }
            Command::CopyURL { entry } => self.entry(&entry).map(|e| copy_entry_field(e, "URL")),
            Command::ClearClipboard => {
                print_value_as_osc52(&[]);
                Ok(())
            }
            Command::OpenDB { path, password } => {
                if self.state.db.is_some() {
                    return Err("Database already opened!".to_string());
                }
                let mut file = File::open(&path).map_err(|err| format!("{}", err))?;
                let db = Database::open(&mut file, DatabaseKey::new().with_password(&password))
                    .map_err(|err| format!("{}", err))?;
                editor_helper.create_db_entries(&db);
                self.state = State::new(Some(db));
                println!("{} successfully opened", path.display());
                Ok(())
            }
            Command::CloseDB => {
                if self.state.db.is_none() {
                    return Err("No database opened!".to_string());
                }
                println!("Closing database!");
                self.state = State::new(None);
                editor_helper.clear_db();
                Ok(())
            }
        }
    }
}

/// This uses OSC52 terminal escape command
/// which makes terminal emulator to copy data to system clipboard
fn print_value_as_osc52(value: &[u8]) {
    use base64::{engine::general_purpose, Engine as _};
    let b64 = general_purpose::STANDARD.encode(value);
    match std::env::var("TMUX") {
        Ok(_) => {
            print!("\x1bPtmux;\x1b\x1b]52;c;{}\x1b\x5c", b64);
        }
        Err(_) => {
            print!("\x1b]52;c;{}", b64);
        }
    }
    println!("Done!");
}

/// Raw bytes of a field value, for copying.
fn value_bytes(value: &Value) -> &[u8] {
    match value {
        Value::Unprotected(value) => value.as_bytes(),
        Value::Protected(value) => value.unsecure(),
        Value::Bytes(value) => value,
    }
}

fn copy_entry_field(entry: &Entry, field_name: &str) {
    match entry.fields.get(field_name) {
        Some(value) => print_value_as_osc52(value_bytes(value)),
        None => eprintln!("{} is not set!", field_name),
    }
}

/// One line of `ls`: `name/` for a group, the title for an entry.
fn print_node_name(node: NodeRef<'_>) {
    match node {
        NodeRef::Group(g) => println!("{}/", g.name),
        NodeRef::Entry(e) => println!("{}", e.get_title().unwrap_or("(no title)")),
    }
}

fn list_node(node: NodeRef<'_>) {
    match node {
        NodeRef::Entry(_) => print_node_name(node),
        NodeRef::Group(g) => g
            .children
            .iter()
            .for_each(|child| print_node_name(child.as_ref())),
    }
}

fn get_totp(e: &Entry) -> Result<String, String> {
    e.get("otp")
        .ok_or("Entry does not have totp!".to_string())
        .and_then(|otp| {
            TOTP::from_url_unchecked(otp).map_err(|err| format!("Error generating totp: {}", err))
        })
        .and_then(|totp| {
            totp.generate_current()
                .map_err(|err| format!("Error generating totp: {}", err))
        })
}

fn print_totp(e: &Entry) {
    match get_totp(e) {
        Ok(totp) => println!("{}", totp),
        Err(err) => eprintln!("{}", err),
    }
}

/// Fields `show` always prints first, in this order, with the placeholder
/// used when the entry doesn't have the field.
const STANDARD_FIELDS: [(&str, &str); 4] = [
    ("Title", "(no title)"),
    ("UserName", "(no username)"),
    ("Password", "(no password)"),
    ("URL", "(no url)"),
];

/// A field value as `show` displays it. Protected values are masked unless
/// `show_hidden` is set.
fn display_value(value: &Value, show_hidden: bool) -> &str {
    match value {
        Value::Bytes(_) => "(bytes)",
        Value::Unprotected(value) => value,
        Value::Protected(value) if show_hidden => {
            std::str::from_utf8(value.unsecure()).unwrap_or("")
        }
        Value::Protected(_) => "*** SECRET ***",
    }
}

/// The text `show` prints for an entry: the standard fields, then every
/// other field sorted by name. With `show_hidden`, an `otp` field is
/// preceded by the current code.
fn format_entry(e: &Entry, show_hidden: bool) -> String {
    const FIELD_NAME_WIDTH: usize = 15;
    let mut out = String::new();
    let mut line = |name: &str, value: &str| {
        out.push_str(&format!("{:>FIELD_NAME_WIDTH$}: {}\n", name, value));
    };

    for (name, placeholder) in STANDARD_FIELDS {
        let value = e.fields.get(name);
        let value = value.map_or(placeholder, |v| display_value(v, show_hidden));
        line(name, value);
    }

    let mut other: Vec<_> = e
        .fields
        .iter()
        .filter(|(name, _)| !STANDARD_FIELDS.iter().any(|(standard, _)| standard == name))
        .collect();
    other.sort_by(|a, b| a.0.cmp(b.0));
    for (name, value) in other {
        if name == "otp" && show_hidden {
            line("otp code", &get_totp(e).unwrap_or_else(|err| err));
        }
        line(name, display_value(value, show_hidden));
    }
    out
}

fn print_node(node: NodeRef<'_>, show_hidden: bool, totp: bool) {
    match (node, totp) {
        (NodeRef::Entry(e), true) => print_totp(e),
        (NodeRef::Entry(e), false) => print!("{}", format_entry(e, show_hidden)),
        (NodeRef::Group(_), true) => eprintln!("Can't show totp for group!"),
        (NodeRef::Group(_), false) => println!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{Group, Node};

    fn entry(fields: &[(&str, &str)]) -> Entry {
        let mut e = Entry::new();
        for (name, value) in fields {
            e.fields
                .insert(name.to_string(), Value::Unprotected(value.to_string()));
        }
        e
    }

    /// Root
    /// └── General/
    ///     ├── Finance/
    ///     ├── Notes        (title, username, password, URL)
    ///     └── Bare         (title only)
    fn sample_executor() -> Executor {
        let mut general = Group::new("General");
        general.children.push(Node::Group(Group::new("Finance")));
        general.children.push(Node::Entry(entry(&[
            ("Title", "Notes"),
            ("UserName", "alice"),
            ("Password", "secret"),
            ("URL", "https://example.com"),
        ])));
        general
            .children
            .push(Node::Entry(entry(&[("Title", "Bare")])));
        let mut database = Database::new(Default::default());
        database.root.children.push(Node::Group(general));
        Executor::new(Some(database))
    }

    /// Parse `line` like the REPL does, then execute it.
    fn run(executor: &mut Executor, line: &str) -> Result<(), String> {
        let cmd = Command::try_parse(line).unwrap_or_else(|err| panic!("{line:?}: {err}"));
        executor.execute(cmd, &mut EditorHelper::new())
    }

    fn dir_depth(executor: &Executor) -> usize {
        executor.state.db.as_ref().unwrap().dir_stack.len()
    }

    #[test]
    fn test_commands_need_an_open_db() {
        let mut executor = Executor::new(None);
        for line in [
            "ls",
            "ls General",
            "cd General",
            "show General/Notes",
            "cp General/Notes",
            "cu General/Notes",
            "cw General/Notes",
        ] {
            assert_eq!(
                run(&mut executor, line),
                Err("Database not opened".to_string()),
                "{line}"
            );
        }
        assert_eq!(
            run(&mut executor, "close"),
            Err("No database opened!".to_string())
        );
        // clearing the clipboard doesn't need a database
        assert_eq!(run(&mut executor, "cx"), Ok(()));
    }

    #[test]
    fn test_list_and_show() {
        let mut executor = sample_executor();
        for line in [
            "ls",
            "ls General",
            "ls General/",
            "ls /General/Notes",
            "show General/Notes",
            "show -s General/Notes",
            "show General",
            // `-t` on an entry without totp prints an error but still succeeds
            "show -t General/Notes",
        ] {
            assert_eq!(run(&mut executor, line), Ok(()), "{line}");
        }
        assert_eq!(
            run(&mut executor, "ls Missing"),
            Err("Missing does not exist!".to_string())
        );
        assert_eq!(
            run(&mut executor, "show General/Missing"),
            Err("General/Missing does not exist!".to_string())
        );
    }

    #[test]
    fn test_copy_commands() {
        let mut executor = sample_executor();
        for cmd in ["cp", "cu", "cw"] {
            assert_eq!(run(&mut executor, &format!("{cmd} General/Notes")), Ok(()));
            // an unset field prints an error but still succeeds
            assert_eq!(run(&mut executor, &format!("{cmd} General/Bare")), Ok(()));
            // groups and missing paths are errors
            assert_eq!(
                run(&mut executor, &format!("{cmd} General")),
                Err("General is not an entry or doesn't exist!".to_string())
            );
            assert_eq!(
                run(&mut executor, &format!("{cmd} General/Missing")),
                Err("General/Missing is not an entry or doesn't exist!".to_string())
            );
        }
    }

    #[test]
    fn test_change_dir() {
        let mut executor = sample_executor();
        assert_eq!(run(&mut executor, "cd General"), Ok(()));
        assert_eq!(executor.get_current_group_name(), Some("General"));
        assert_eq!(dir_depth(&executor), 1);

        // relative to the current group
        assert_eq!(run(&mut executor, "show Notes"), Ok(()));

        assert_eq!(
            run(&mut executor, "cd Notes"),
            Err("Notes is not a group or doesn't exist!".to_string())
        );
        assert!(run(&mut executor, "cd Missing").is_err());
        assert_eq!(executor.get_current_group_name(), Some("General"));

        assert_eq!(run(&mut executor, "cd Finance"), Ok(()));
        assert_eq!(dir_depth(&executor), 2);
        // `..` works in ls/show/cp paths too, without changing the group
        for line in ["ls ..", "ls ../..", "show ../Notes", "cp ../Notes"] {
            assert_eq!(run(&mut executor, line), Ok(()), "{line}");
        }
        assert_eq!(dir_depth(&executor), 2);
        assert_eq!(run(&mut executor, "cd .."), Ok(()));
        assert_eq!(dir_depth(&executor), 1);
        assert_eq!(run(&mut executor, "cd"), Ok(()));
        assert_eq!(dir_depth(&executor), 0);
    }

    #[test]
    fn test_open_and_close() {
        let mut executor = sample_executor();
        assert_eq!(
            run(&mut executor, "open some.kdbx pw"),
            Err("Database already opened!".to_string())
        );
        assert_eq!(run(&mut executor, "close"), Ok(()));
        assert_eq!(executor.get_db().map(|_| ()), None);
        assert_eq!(
            run(&mut executor, "ls"),
            Err("Database not opened".to_string())
        );

        // opening a file that doesn't exist fails and leaves no db open
        assert!(run(&mut executor, "open /nonexistent/kpcli-test.kdbx pw").is_err());
        assert!(executor.get_db().is_none());
    }

    #[test]
    fn test_get_totp() {
        assert_eq!(
            get_totp(&entry(&[("Title", "x")])),
            Err("Entry does not have totp!".to_string())
        );

        let e = entry(&[(
            "otp",
            "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Test",
        )]);
        let code = get_totp(&e).unwrap();
        assert_eq!(code.len(), 6, "{code}");
        assert!(code.chars().all(|c| c.is_ascii_digit()), "{code}");

        let bad = entry(&[("otp", "not a url")]);
        let err = get_totp(&bad).unwrap_err();
        assert!(err.starts_with("Error generating totp"), "{err}");
    }

    /// `format_entry` output as (name, value) pairs, one per line.
    fn entry_lines(e: &Entry, show_hidden: bool) -> Vec<(String, String)> {
        format_entry(e, show_hidden)
            .lines()
            .map(|line| {
                let (name, value) = line.split_once(": ").unwrap();
                (name.trim_start().to_string(), value.to_string())
            })
            .collect()
    }

    fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
        expected
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_show_field_order() {
        let mut e = entry(&[
            ("zeta", "last"),
            ("URL", "https://bank.example"),
            ("Notes", "pin is 1234"),
            ("Password", "secret"),
            ("Title", "Bank"),
            ("alpha", "first"),
            ("UserName", "alice"),
        ]);
        e.fields
            .insert("Bytes".to_string(), Value::Bytes(vec![1, 2, 3]));
        let expected = pairs(&[
            ("Title", "Bank"),
            ("UserName", "alice"),
            ("Password", "secret"),
            ("URL", "https://bank.example"),
            ("Bytes", "(bytes)"),
            ("Notes", "pin is 1234"),
            ("alpha", "first"),
            ("zeta", "last"),
        ]);
        // the same on every run, despite fields being a HashMap
        for _ in 0..10 {
            assert_eq!(entry_lines(&e, false), expected);
        }
    }

    #[test]
    fn test_show_placeholders_for_missing_standard_fields() {
        assert_eq!(
            entry_lines(&entry(&[("Notes", "n")]), false),
            pairs(&[
                ("Title", "(no title)"),
                ("UserName", "(no username)"),
                ("Password", "(no password)"),
                ("URL", "(no url)"),
                ("Notes", "n"),
            ])
        );
    }

    #[test]
    fn test_show_hidden_values() {
        let mut e = entry(&[("Title", "Bank")]);
        e.fields.insert(
            "Password".to_string(),
            Value::Protected("secret".to_string().into()),
        );
        e.fields.insert(
            "otp".to_string(),
            Value::Protected(
                "otpauth://totp/T:a?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
                    .to_string()
                    .into(),
            ),
        );

        let masked = entry_lines(&e, false);
        assert_eq!(masked[2], pairs(&[("Password", "*** SECRET ***")])[0]);
        // no otp code line without show_hidden
        assert_eq!(masked[4..], pairs(&[("otp", "*** SECRET ***")]));

        let shown = entry_lines(&e, true);
        assert_eq!(shown[2], pairs(&[("Password", "secret")])[0]);
        // the otp code comes right before the otp field
        assert_eq!(shown[4].0, "otp code");
        assert_eq!(shown[4].1.len(), 6, "{:?}", shown[4]);
        assert!(shown[5].1.starts_with("otpauth://"), "{:?}", shown[5]);
        assert_eq!(shown.len(), 6);
    }
}
