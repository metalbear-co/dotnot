//! Why a file couldn't be classified.

use std::{io, path::PathBuf};

/// A file that couldn't be classified.
///
/// A file that is readable but not an executable dotnot knows is not an error: it's
/// [`DotnetKind::NotDotnet`](crate::DotnetKind::NotDotnet).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("failed to open {}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read {}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The file starts as a PE image, but its headers are cut short or unknown.
    #[error("malformed PE headers")]
    MalformedPe(#[source] PeError),
}

/// What is wrong with a PE image's headers.
///
/// Only the headers dotnot reads are checked. Broken resources are not an error: they can't
/// say the image is the muxer, so the answer is still decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeError {
    #[error("the DOS header ends before its 64 bytes do")]
    TruncatedDosHeader,
    #[error("the NT headers at {offset:#x} end before the optional header does")]
    TruncatedNtHeaders { offset: u64 },
    #[error("the {size}-byte optional header is too small for its own fields")]
    OptionalHeaderTooSmall { size: u16 },
    #[error("unknown optional header magic {magic:#06x}")]
    UnknownOptionalHeaderMagic { magic: u16 },
    #[error("the section table at {offset:#x} ends before its last section does")]
    TruncatedSectionTable { offset: u64 },
}
