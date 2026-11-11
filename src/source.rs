//! Where the bytes come from: a file read piece by piece, or bytes already in memory.
//!
//! The classifier reads through [`Source`], so a file is never read whole into memory, and
//! the same code serves `classify` and `classify_bytes`.

use std::{
    convert::Infallible,
    fs::File,
    io::{self, ErrorKind, Read, Seek, SeekFrom},
};

/// Bytes the classifier can read at any offset.
pub(crate) trait Source {
    /// [`Infallible`] for bytes in memory, so `classify_bytes` can't fail to read.
    type Error;

    /// Reads up to `buf.len()` bytes at `offset`, and returns how many it read.
    ///
    /// It reads fewer only at the end of the input, and none past it.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

impl Source for &[u8] {
    type Error = Infallible;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize, Infallible> {
        let start = usize::try_from(offset).map_or(self.len(), |offset| offset.min(self.len()));
        let len = buf.len().min(self.len() - start);
        buf[..len].copy_from_slice(&self[start..start + len]);
        Ok(len)
    }
}

/// A file, read at an offset with a seek and as many reads as it takes.
pub(crate) struct FileSource(pub(crate) File);

impl Source for FileSource {
    type Error = io::Error;

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.0.seek(SeekFrom::Start(offset))?;
        let mut filled = 0;
        while filled < buf.len() {
            match self.0.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(filled)
    }
}

/// Why the classifier stopped, before the caller adds its context.
#[derive(Debug)]
pub(crate) enum Failure<E> {
    /// The source failed to read.
    Read(E),
}
