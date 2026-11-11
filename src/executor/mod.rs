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
use state::State;
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

    pub fn execute(
        &mut self,
        command: Command,
        editor_helper: &mut EditorHelper,
    ) -> Result<(), String> {
        match command {
            Command::ListDir { path } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or("Database not opened".to_string())?;
                let group = db.get_current_group();
                if let Some(node) = db.get_node(group, &path) {
                    list_node(node);
                    Ok(())
                } else {
                    Err(format!("{} does not exist!", path))
                }
            }
            Command::ChangeDir { path } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or("Database not opened".to_string())?;
                match db.change_current_group(&path) {
                    false => Err(format!("{} is not a group or doesn't exist!", path)),
                    true => {
                        editor_helper.set_dir_stack(db.dir_stack.clone());
                        Ok(())
                    }
                }
            }
            Command::Show {
                show_hidden,
                entry,
                totp,
            } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or("Database not opened".to_string())?;
                let group = db.get_current_group();
                if let Some(node) = db.get_node(group, &entry) {
                    print_node(node, show_hidden, totp);
                    Ok(())
                } else {
                    Err(format!("{} does not exist!", entry))
                }
            }
            Command::CopyPassword { entry } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or("Database not opened".to_string())?;
                let group = db.get_current_group();
                match db.get_node(group, &entry) {
                    Some(NodeRef::Group(_)) | None => {
                        Err(format!("{} is not a group or doesn't exist!", entry))
                    }
                    Some(NodeRef::Entry(e)) => {
                        copy_entry_field(e, "Password");
                        Ok(())
                    }
                }
            }
            Command::CopyUsername { entry } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or("Database not opened".to_string())?;
                let group = db.get_current_group();
                match db.get_node(group, &entry) {
                    Some(NodeRef::Group(_)) | None => {
                        Err(format!("{} is not a group or doesn't exist!", entry))
                    }
                    Some(NodeRef::Entry(e)) => {
                        copy_entry_field(e, "UserName");
                        Ok(())
                    }
                }
            }
            Command::CopyURL { entry } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or("Database not opened".to_string())?;
                let group = db.get_current_group();
                match db.get_node(group, &entry) {
                    Some(NodeRef::Group(_)) | None => {
                        Err(format!("{} is not a group or doesn't exist!", entry))
                    }
                    Some(NodeRef::Entry(e)) => {
                        copy_entry_field(e, "URL");
                        Ok(())
                    }
                }
            }
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

fn copy_entry_field(entry: &Entry, field_name: &str) {
    match entry.fields.get(field_name) {
        Some(Value::Unprotected(value)) => {
            print_value_as_osc52(value.as_bytes());
        }
        Some(Value::Protected(value)) => {
            print_value_as_osc52(value.unsecure());
        }
        Some(Value::Bytes(value)) => {
            print_value_as_osc52(value);
        }
        None => {
            eprintln!("{} is not set!", field_name);
        }
    }
}

fn list_node(node: NodeRef<'_>) {
    match node {
        NodeRef::Entry(e) => {
            let title = e.get_title().unwrap_or("(no title");
            println!("{}", title);
        }
        NodeRef::Group(g) => {
            for node in &g.children {
                match node.as_ref() {
                    NodeRef::Group(g) => {
                        println!("{}/", g.name);
                    }
                    NodeRef::Entry(e) => {
                        let title = e.get_title().unwrap_or("(no title");
                        println!("{}", title);
                    }
                }
            }
        }
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

fn print_node(node: NodeRef<'_>, show_hidden: bool, totp: bool) {
    const FIELD_NAME_WIDTH: usize = 15;

    fn get_value(val: &Value, show_hidden: bool) -> &str {
        match val {
            Value::Bytes(_) => "(bytes)",
            Value::Unprotected(val) => val,
            Value::Protected(val) => {
                if show_hidden {
                    let val = std::str::from_utf8(val.unsecure()).unwrap_or("");
                    val
                } else {
                    "*** SECRET ***"
                }
            }
        }
    }

    match node {
        NodeRef::Entry(e) => {
            if totp {
                print_totp(e);
                return;
            }
            let title = e
                .fields
                .get("Title")
                .map(|val| get_value(val, show_hidden))
                .unwrap_or("(no title)");
            let username = e
                .fields
                .get("UserName")
                .map(|val| get_value(val, show_hidden))
                .unwrap_or("(no username)");
            let password = e
                .fields
                .get("Password")
                .map(|val| get_value(val, show_hidden))
                .unwrap_or("(no password)");
            println!("{:>FIELD_NAME_WIDTH$}: {}", "Title", title);
            println!("{:>FIELD_NAME_WIDTH$}: {}", "UserName", username);
            println!("{:>FIELD_NAME_WIDTH$}: {}", "Password", password);

            for (field_name, field_value) in &e.fields {
                if field_name == "otp" && show_hidden {
                    let val = match get_totp(e) {
                        Ok(val) => val,
                        Err(err) => err,
                    };
                    println!("{:>FIELD_NAME_WIDTH$}: {}", "otp code", val);
                }
                if field_name != "Title" && field_name != "UserName" && field_name != "Password" {
                    println!(
                        "{:>FIELD_NAME_WIDTH$}: {}",
                        field_name,
                        get_value(field_value, show_hidden),
                    );
                }
            }
        }
        NodeRef::Group(_) => {
            if totp {
                eprintln!("Can't show totp for group!");
            } else {
                println!();
            }
        }
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
            // groups and missing paths are errors (exact text is a known bug,
            // it says "is not a group" for an entry target)
            assert!(run(&mut executor, &format!("{cmd} General")).is_err());
            assert!(run(&mut executor, &format!("{cmd} General/Missing")).is_err());
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
}
