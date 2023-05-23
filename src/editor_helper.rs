use std::borrow::Cow;

use rustyline::{
    completion::Completer, highlight::Highlighter, hint::Hinter, validate::Validator, Helper,
};

pub struct PasswordInput;

impl Highlighter for PasswordInput {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Cow::Owned("*".repeat(line.len()))
    }

    fn highlight_char(&self, _line: &str, _pos: usize) -> bool {
        true
    }
}

impl Validator for PasswordInput {}

impl Hinter for PasswordInput {
    type Hint = String;
}

impl Completer for PasswordInput {
    type Candidate = String;
}

impl Helper for PasswordInput {}
