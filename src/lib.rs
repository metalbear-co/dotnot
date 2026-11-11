#![forbid(unsafe_code)]

mod error;
mod kind;
mod pe;
mod scan;
mod source;

pub use error::{Error, PeError};
pub use kind::DotnetKind;

use source::{Failure, FileSource, Source};
use std::{fs::File, path::Path};

/// Classifies the executable at `path`.
///
/// The file is read in pieces, never whole: see the crate docs for which pieces, and why.
///
/// # Errors
///
/// * [`Error::Open`] or [`Error::Read`] - the file can't be read.
/// * [`Error::MalformedPe`] - the file starts as a PE image, but its headers are broken.
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
        Failure::Pe(error) => Error::MalformedPe(error),
    })
}

/// Classifies an executable already in memory.
///
/// It decides exactly as [`classify`] does for a file with these bytes.
///
/// # Errors
///
/// [`Error::MalformedPe`] when the bytes start as a PE image, but its headers are broken.
pub fn classify_bytes(bytes: &[u8]) -> Result<DotnetKind, Error> {
    let mut source = bytes;
    classify_source(&mut source).map_err(|failure| match failure {
        Failure::Read(never) => match never {},
        Failure::Pe(error) => Error::MalformedPe(error),
    })
}

/// The decision, for any source of bytes.
fn classify_source<S: Source>(source: &mut S) -> Result<DotnetKind, Failure<S::Error>> {
    let pe = pe::Headers::read(source)?;
    // An apphost is native code, so a CLR header settles it without scanning the file.
    if pe.as_ref().is_some_and(pe::Headers::has_clr_header) {
        return Ok(DotnetKind::FrameworkAssembly);
    }

    let found = scan::scan(source).map_err(Failure::Read)?;
    if let Some(header_offset) = found.bundle_header_offset {
        return Ok(DotnetKind::Apphost {
            single_file: header_offset != 0,
        });
    }

    let is_muxer = match &pe {
        Some(headers) => headers.is_muxer(source).map_err(Failure::Read)?,
        None => false,
    };
    Ok(if is_muxer {
        DotnetKind::Muxer
    } else {
        DotnetKind::NotDotnet
    })
}
