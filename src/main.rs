mod editor_helper;
mod executor;
mod opt;

use clap::Parser;
use editor_helper::PasswordInput;
use executor::{Command, Executor};
use keepass::{Database, DatabaseOpenError};
use opt::Opts;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::fs::File;
use std::path::PathBuf;

fn open_db(file: &PathBuf, password: &str) -> Result<Database, DatabaseOpenError> {
    let mut file = File::open(file)?;
    Database::open(&mut file, Some(password), None)
}

fn main() -> Result<(), DatabaseOpenError> {
    let opts = Opts::parse();

    // Open KeePass database if file was given in cmdline
    let db: Option<Database> = if let Some(ref file) = opts.db_file {
        let password = match opts.password {
            Some(password) => password,
            None => {
                let mut rl = Editor::new().unwrap();
                rl.set_helper(Some(PasswordInput));
                match rl.readline("Enter password: ") {
                    Ok(line) => line,
                    Err(err) => {
                        eprintln!("Error reading line: {}", err);
                        return Ok(());
                    }
                }
            }
        };
        Some(open_db(file, &password)?)
    } else {
        None
    };

    let mut executor = Executor::new(db);

    if let Some(cmd) = opts.command {
        if let Err(err) = executor.execute(cmd) {
            eprintln!("{}", err);
        };
        return Ok(());
    }

    println!("\nType 'help' for a description of available commands.");
    println!("Type 'help <command>' for details on individual commands.\n");

    let mut rl = Editor::<()>::new().unwrap();
    loop {
        let readline = if let Some(curr_group) = &executor.get_current_group_name() {
            rl.readline(&format!("{}>> ", curr_group))
        } else {
            rl.readline(">> ")
        };
        match readline {
            Ok(line) => {
                let command = match Command::try_parse(&line) {
                    Err(err) => {
                        err.print();
                        continue;
                    }
                    Ok(cmd) => cmd,
                };
                rl.add_history_entry(line.as_str());
                if let Err(err) = executor.execute(command) {
                    eprintln!("{}", err);
                };
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
