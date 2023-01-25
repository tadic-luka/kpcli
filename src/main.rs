mod command;
mod opt;
mod state;

use clap::Parser;
use command::Command;
use keepass::{Database, DatabaseOpenError, NodeRef};
use opt::Opts;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use state::State;
use std::fs::File;

fn print_node<'a>(node: NodeRef<'a>) {
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
                print_node(node);
            } else {
                eprintln!("{} does not exist!", path);
            }
        }
        Command::ChangeDir { path } => {
            match db.change_current_group(&path) {
                false => {
                    eprintln!("{} is not a group or doesn't exist!", path);
                }
                true => {}
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
