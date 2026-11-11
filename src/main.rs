mod executor;
mod opt;

use clap::Parser;
use executor::{open_db, Command, EditorHelper, Executor, PasswordInput};
use keepass::error::DatabaseOpenError;
use opt::Opts;
use rustyline::error::ReadlineError;
use rustyline::Editor;

/// Prompt for the database password without echoing it.
/// Prints the error and returns `None` if the line can't be read.
fn read_password() -> Option<String> {
    let mut rl = Editor::new().unwrap();
    rl.set_helper(Some(PasswordInput));
    match rl.readline("Enter password: ") {
        Ok(line) => Some(line),
        Err(err) => {
            eprintln!("Error reading line: {}", err);
            None
        }
    }
}

/// Run one command, printing its error if it fails.
fn run_command(executor: &mut Executor, command: Command, editor_helper: &mut EditorHelper) {
    if let Err(err) = executor.execute(command, editor_helper) {
        eprintln!("{}", err);
    }
}

fn main() -> Result<(), DatabaseOpenError> {
    let opts = Opts::parse();

    // Open KeePass database if file was given in cmdline
    let db = match &opts.db_file {
        Some(file) => {
            let Some(password) = opts.password.or_else(read_password) else {
                return Ok(());
            };
            Some(open_db(file, &password)?)
        }
        None => None,
    };

    let mut executor = Executor::new(db);

    if let Some(cmd) = opts.command {
        run_command(&mut executor, cmd, &mut EditorHelper::new());
        return Ok(());
    }

    println!("\nType 'help' for a description of available commands.");
    println!("Type 'help <command>' for details on individual commands.\n");

    let mut editor_helper = EditorHelper::new();
    if let Some(db) = executor.get_db() {
        editor_helper.create_db_entries(db);
    }
    let mut rl = Editor::new().unwrap();
    rl.set_helper(Some(editor_helper));
    loop {
        let prompt = match executor.get_current_group_name() {
            Some(group) => format!("{}>> ", group),
            None => ">> ".to_string(),
        };
        match rl.readline(&prompt) {
            Ok(line) => {
                let command = match Command::try_parse(&line) {
                    Err(err) => {
                        let _ = err.print();
                        continue;
                    }
                    Ok(cmd) => cmd,
                };
                rl.add_history_entry(line.as_str());
                run_command(&mut executor, command, rl.helper_mut().unwrap());
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
