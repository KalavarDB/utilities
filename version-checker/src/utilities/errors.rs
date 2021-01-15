use std::fmt;
use serde::__private::Formatter;

pub enum Errors {
    /// # Errors for the Security Database
    // Unable to update advisory database
    DBUpdateFailed,

    //  Unable to read advisory database
    DBUnreadable,

    // Unable to write advisory database
    DBNotWriteable,

    /// # Errors for the Cargo.toml file
    // Unable to locate Cargo.toml
    CrateFileNotFound,
}

pub enum DisplayMode {
    Debug,
    User,
}

pub struct VerificationError {
    pub inner: Errors,
}

impl fmt::Debug for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        log(self, f, DisplayMode::Debug)
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        log(self, f, DisplayMode::User)
    }
}


impl VerificationError {
    pub fn new(inner: Errors) -> VerificationError {
        VerificationError {
            inner
        }
    }
}

pub fn log(_e: &VerificationError, f: &mut fmt::Formatter, display_mode: DisplayMode) -> fmt::Result {
    return match display_mode {
        DisplayMode::Debug => {
            write!(f, "This is a debug displayed error")
        }
        DisplayMode::User => {
            write!(f, "This is a user displayed error")
        }
    };
}