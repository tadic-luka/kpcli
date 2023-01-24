mod opt;

use clap::Parser;
use keepass::{Database, DatabaseOpenError, NodeRef};
use opt::Opts;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::fs::File;

fn print_dir(group: &keepass::Group) {
    for node in &group.children {
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

fn handle_command(db: Option<&mut Database>, command: &str) {
    let db = match db {
        Some(db) => db,
        None => {
            eprintln!("Database not opened!");
            return;
        }
    };

    match command {
        "ls" => {
            print_dir(&db.root);
        }
        _ => {
            eprintln!("Command not yet supported!");
        }
    }
}

fn main() -> Result<(), DatabaseOpenError> {
    let opts = Opts::parse();
    // Open KeePass database
    let mut file = File::open(&opts.db_file)?;

    let mut db: Option<Database> = match opts.password.as_ref() {
        Some(password) => Some(Database::open(&mut file, Some(password), None)?),
        _ => None,
    };

    let mut rl = Editor::<()>::new().unwrap();
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                handle_command(db.as_mut(), &line);
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
