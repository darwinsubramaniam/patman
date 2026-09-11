//! One error type, carrying a message meant to be read by a human (or by an
//! agent deciding what to do next). No secret ever reaches it: token values are
//! never interpolated into an error string anywhere in this crate.

use std::fmt;

#[derive(Debug)]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error(e.to_string())
    }
}

pub fn bail<T, S: Into<String>>(msg: S) -> Result<T> {
    Err(Error(msg.into()))
}

/// Attach context to an io error without losing the underlying cause.
pub trait Context<T> {
    fn ctx<S: fmt::Display>(self, what: S) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn ctx<S: fmt::Display>(self, what: S) -> Result<T> {
        self.map_err(|e| Error(format!("{what}: {e}")))
    }
}
