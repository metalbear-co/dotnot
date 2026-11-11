#![doc = include_str!("../README.md")]
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

    // The usage line names the muxer only where there's no version resource to ask. A script
    // or a text file can hold the same words, so other formats never look for it.
    let find_usage = pe.is_none() && is_elf_or_mach_o(source).map_err(Failure::Read)?;
    let found = scan::scan(source, find_usage).map_err(Failure::Read)?;
    if let Some(header_offset) = found.bundle_header_offset {
        return Ok(DotnetKind::Apphost {
            single_file: header_offset != 0,
        });
    }

    let is_muxer = match &pe {
        Some(headers) => headers.is_muxer(source).map_err(Failure::Read)?,
        None => found.usage,
    };
    Ok(if is_muxer {
        DotnetKind::Muxer
    } else {
        DotnetKind::NotDotnet
    })
}

/// The file starts with an ELF or a Mach-O magic number: the formats of a Linux or macOS
/// muxer.
fn is_elf_or_mach_o<S: Source>(source: &mut S) -> Result<bool, S::Error> {
    const MAGICS: [[u8; 4]; 7] = [
        *b"\x7fELF",
        // Thin Mach-O, 32-bit and 64-bit, little-endian as on x86-64 and arm64.
        [0xce, 0xfa, 0xed, 0xfe],
        [0xcf, 0xfa, 0xed, 0xfe],
        // Thin Mach-O, big-endian.
        [0xfe, 0xed, 0xfa, 0xce],
        [0xfe, 0xed, 0xfa, 0xcf],
        // Universal (fat) Mach-O, whose header is always big-endian, 32-bit and 64-bit.
        [0xca, 0xfe, 0xba, 0xbe],
        [0xca, 0xfe, 0xba, 0xbf],
    ];
    let mut magic = [0u8; 4];
    let read = source.read_at(0, &mut magic)?;
    Ok(read == magic.len() && MAGICS.contains(&magic))
}
