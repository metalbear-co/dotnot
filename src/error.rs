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
}
