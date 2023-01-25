mod command;
mod opt;
mod state;

use clap::Parser;
use command::Command;
use keepass::{Database, DatabaseOpenError, NodeRef, Value};
use opt::Opts;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use state::State;
use std::fs::File;

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

fn handle_command<'a>(state: &'a mut State, command: &str) {
    let db = match &mut state.db {
        Some(db) => db,
        None => {
            eprintln!("Database not opened!");
            return;
        }
    };
    let command = match Command::try_parse(command) {
        Err(err) => {
            err.print();
            return;
        }
        Ok(cmd) => cmd,
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
    }
}

fn main() -> Result<(), DatabaseOpenError> {
    let opts = Opts::parse();
    // Open KeePass database
    let mut file = File::open(&opts.db_file)?;

    let db: Option<Database> = match opts.password.as_ref() {
        Some(password) => Some(Database::open(&mut file, Some(password), None)?),
        _ => None,
    };

    let mut state = State::new(db);

    let mut rl = Editor::<()>::new().unwrap();
    loop {
        let readline = if let Some(db) = &state.db {
            rl.readline(&format!("{}>> ", db.get_current_group().name))
        } else {
            rl.readline(">> ")
        };
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                handle_command(&mut state, &line);
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    Ok(())
}
