mod command;
mod state;

pub use command::Command;
use keepass::{Database, Entry, NodeRef, Value};
use state::State;

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

    pub fn execute(&mut self, command: Command) {
        let db = match &mut self.state.db {
            Some(db) => db,
            None => {
                eprintln!("Database not opened!");
                return;
            }
        };

        match command {
            Command::ListDir { path } => {
                let group = db.get_current_group();
                if let Some(node) = db.get_node(&group, &path) {
                    list_node(node);
                } else {
                    eprintln!("{} does not exist!", path);
                }
            }
            Command::ChangeDir { path } => match db.change_current_group(&path) {
                false => {
                    eprintln!("{} is not a group or doesn't exist!", path);
                }
                true => {}
            },
            Command::Show { show_hidden, entry } => {
                let group = db.get_current_group();
                if let Some(node) = db.get_node(&group, &entry) {
                    print_node(node, show_hidden)
                } else {
                    eprintln!("{} does not exist!", entry);
                }
            }
            Command::CopyPassword { entry } => {
                let group = db.get_current_group();
                match db.get_node(&group, &entry) {
                    Some(NodeRef::Group(_)) | None => {
                        eprintln!("{} is not a group or doesn't exist!", entry);
                    }
                    Some(NodeRef::Entry(e)) => copy_entry_field(e, "Password"),
                }
            }
            Command::CopyUsername { entry } => {
                let group = db.get_current_group();
                match db.get_node(&group, &entry) {
                    Some(NodeRef::Group(_)) | None => {
                        eprintln!("{} is not a group or doesn't exist!", entry);
                    }
                    Some(NodeRef::Entry(e)) => copy_entry_field(e, "UserName"),
                }
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
    println!("Copied to clipboard!");
}

fn copy_entry_field<'a>(entry: &'a Entry, field_name: &str) {
    match entry.fields.get(field_name) {
        Some(Value::Unprotected(value)) => {
            print_value_as_osc52(value.as_bytes());
        }
        Some(Value::Protected(value)) => {
            print_value_as_osc52(value.unsecure());
        }
        Some(Value::Bytes(value)) => {
            print_value_as_osc52(&value);
        }
        None => {
            eprintln!("{} is not set!", field_name);
        }
    }
}

fn list_node<'a>(node: NodeRef<'a>) {
    match node {
        NodeRef::Entry(e) => {
            let title = e.get_title().unwrap_or("(no title");
            println!("{}", title);
        }
        NodeRef::Group(g) => {
            for node in &g.children {
                match node.to_ref() {
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

fn print_node<'a>(node: NodeRef<'a>, show_hidden: bool) {
    const FIELD_NAME_WIDTH: usize = 15;

    fn get_value(val: &Value, show_hidden: bool) -> &str {
        match val {
            Value::Bytes(_) => "(bytes)",
            Value::Unprotected(val) => &val,
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
            println!("");
        }
    }
}
