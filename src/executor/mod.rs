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
                    .ok_or(format!("Database not opened"))?;
                let group = db.get_current_group();
                if let Some(node) = db.get_node(&group, &path) {
                    Ok(list_node(node))
                } else {
                    Err(format!("{} does not exist!", path))
                }
            }
            Command::ChangeDir { path } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or(format!("Database not opened"))?;
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
                    .ok_or(format!("Database not opened"))?;
                let group = db.get_current_group();
                if let Some(node) = db.get_node(&group, &entry) {
                    Ok(print_node(node, show_hidden, totp))
                } else {
                    Err(format!("{} does not exist!", entry))
                }
            }
            Command::CopyPassword { entry } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or(format!("Database not opened"))?;
                let group = db.get_current_group();
                match db.get_node(&group, &entry) {
                    Some(NodeRef::Group(_)) | None => {
                        Err(format!("{} is not a group or doesn't exist!", entry))
                    }
                    Some(NodeRef::Entry(e)) => Ok(copy_entry_field(e, "Password")),
                }
            }
            Command::CopyUsername { entry } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or(format!("Database not opened"))?;
                let group = db.get_current_group();
                match db.get_node(&group, &entry) {
                    Some(NodeRef::Group(_)) | None => {
                        Err(format!("{} is not a group or doesn't exist!", entry))
                    }
                    Some(NodeRef::Entry(e)) => Ok(copy_entry_field(e, "UserName")),
                }
            }
            Command::CopyURL { entry } => {
                let db = self
                    .state
                    .db
                    .as_mut()
                    .ok_or(format!("Database not opened"))?;
                let group = db.get_current_group();
                match db.get_node(&group, &entry) {
                    Some(NodeRef::Group(_)) | None => {
                        Err(format!("{} is not a group or doesn't exist!", entry))
                    }
                    Some(NodeRef::Entry(e)) => Ok(copy_entry_field(e, "URL")),
                }
            }
            Command::ClearClipboard => Ok(print_value_as_osc52(&[])),
            Command::OpenDB { path, password } => {
                if self.state.db.is_some() {
                    return Err(format!("Database already opened!"));
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
                    return Err(format!("No database opened!"));
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
        .ok_or(format!("Entry does not have totp!"))
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

fn print_node<'a>(node: NodeRef<'a>, show_hidden: bool, totp: bool) {
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
                println!("");
            }
        }
    }
}
