#![forbid(unsafe_code)]

mod error;
mod kind;
mod scan;
mod source;

pub use error::Error;
pub use kind::DotnetKind;

use source::{Failure, FileSource, Source};
use std::{fs::File, path::Path};

/// Classifies the executable at `path`.
///
/// The file is read in pieces, never whole: see the crate docs for which pieces, and why.
///
/// # Errors
///
/// [`Error::Open`] or [`Error::Read`] when the file can't be read.
pub fn classify(path: impl AsRef<Path>) -> Result<DotnetKind, Error> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|source| Error::Open {
        path: path.to_owned(),
        source,
    })?;
    classify_source(&mut FileSource(file)).map_err(|failure| match failure {
        Failure::Read(source) => Error::Read {
            path: path.to_owned(),
            source,
        },
    })
}

/// Classifies an executable already in memory.
///
/// It decides exactly as [`classify`] does for a file with these bytes.
///
/// # Errors
///
/// None yet: bytes in memory always read.
pub fn classify_bytes(bytes: &[u8]) -> Result<DotnetKind, Error> {
    let mut source = bytes;
    classify_source(&mut source).map_err(|failure| match failure {
        Failure::Read(never) => match never {},
    })
}

/// The decision, for any source of bytes.
fn classify_source<S: Source>(source: &mut S) -> Result<DotnetKind, Failure<S::Error>> {
    let found = scan::scan(source).map_err(Failure::Read)?;
    Ok(match found.bundle_header_offset {
        Some(header_offset) => DotnetKind::Apphost {
            single_file: header_offset != 0,
        },
        None => DotnetKind::NotDotnet,
    })
}
