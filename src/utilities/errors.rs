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

    /// # Errors for web access
    // unable to retreive crate info
    CrateNotAvailable,

    /// # Errors for parsing
    // Unable to parse version
    VersionUnacceptable,
    CrateParseFailed,
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

pub fn log(e: &VerificationError, f: &mut fmt::Formatter, display_mode: DisplayMode) -> fmt::Result {
    return match display_mode {
        DisplayMode::Debug => {
            match e.inner {
                Errors::DBUpdateFailed => {
                    write!(f, "Failed to update the advisory database")
                }
                Errors::DBUnreadable => {
                    write!(f, "Failed to read the advisory database")
                }
                Errors::DBNotWriteable => {
                    write!(f, "Failed to write the advisory database")
                }
                Errors::CrateFileNotFound => {
                    write!(f, "Failed to locate package manifest (Cargo.toml)")
                }
                Errors::CrateNotAvailable => {
                    write!(f, "Unable to fetch from Crates.io")
                }
                Errors::VersionUnacceptable => {
                    write!(f, "Failed to parse the supplied version number")
                }
                Errors::CrateParseFailed => {
                    write!(f, "Failed to parse crate")
                }
            }
        }
        DisplayMode::User => {
            match e.inner {
                Errors::DBUpdateFailed => {
                    write!(f, "Failed to update the advisory database")
                }
                Errors::DBUnreadable => {
                    write!(f, "Failed to read the advisory database")
                }
                Errors::DBNotWriteable => {
                    write!(f, "Failed to write the advisory database")
                }
                Errors::CrateFileNotFound => {
                    write!(f, "Failed to locate package manifest (Cargo.toml)")
                }
                Errors::CrateNotAvailable => {
                    write!(f, "Unable to fetch from Crates.io")
                }
                Errors::VersionUnacceptable => {
                    write!(f, "Failed to parse the supplied version number")
                }
                Errors::CrateParseFailed => {
                    write!(f, "Failed to parse crate")
                }
            }
        }
    };
}