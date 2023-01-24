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

fn main() -> Result<(), DatabaseOpenError> {
    let opts = Opts::parse();
    // Open KeePass database
    let mut file = File::open(&opts.file)?;
    let db = Database::open(
        &mut file,
        Some(&opts.password), // password
        None,                 // keyfile
    )?;

    let mut rl = Editor::<()>::new().unwrap();
    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                if line == "ls" {
                    print_dir(&db.root);
                } else {
                    println!("Invalid command {}", line);
                }
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
