mod executor;
mod opt;

use clap::Parser;
use executor::{Command, Executor};
use keepass::{Database, DatabaseOpenError};
use opt::Opts;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::fs::File;

fn main() -> Result<(), DatabaseOpenError> {
    let opts = Opts::parse();
    // Open KeePass database
    let mut file = File::open(&opts.db_file)?;

    let db: Option<Database> = match opts.password.as_ref() {
        Some(password) => Some(Database::open(&mut file, Some(password), None)?),
        _ => None,
    };

    let mut executor = Executor::new(db);

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
                executor.execute(command);
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
