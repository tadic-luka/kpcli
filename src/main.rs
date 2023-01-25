mod command;
mod opt;

use clap::Parser;
use command::Command;
use keepass::{Database, DatabaseOpenError, Group, Node, NodeRef};
use opt::Opts;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::fs::File;

/// recursively try to get given path
pub fn get<'a>(group: &'a Group, path: &[&str]) -> Option<NodeRef<'a>> {
    if path.is_empty() {
        Some(NodeRef::Group(group))
    } else {
        if path.len() == 1 {
            let head = path[0];
            if head == "." || head == "./" || head == "" {
                return Some(NodeRef::Group(group));
            }
            group.children.iter().find_map(|n| match n {
                Node::Group(g) if g.name == head => Some(n.to_ref()),
                Node::Entry(e) => {
                    e.get_title()
                        .and_then(|t| if t == head { Some(n.to_ref()) } else { None })
                }
                _ => None,
            })
        } else {
            let head = path[0];
            let tail = &path[1..path.len()];

            let head_group = group.children.iter().find_map(|n| match n {
                Node::Group(g) if g.name == head => Some(g),
                _ => None,
            })?;

            get(&head_group, tail)
        }
    }
}

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

fn handle_command<'a>(db: Option<&'a mut Database>, command: &str) {
    let db = match db {
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
            let paths: Vec<&str> = path.split("/").collect();
            if let Some(node) = get(&db.root, &paths) {
                print_node(node);
            } else {
                eprintln!("{} does not exist!", path);
            }
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
