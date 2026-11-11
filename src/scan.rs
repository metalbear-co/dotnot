//! The streaming search for the apphost's bundle marker, and the Unix muxer's usage line.
//!
//! Every apphost keeps a 40-byte placeholder in its data: an 8-byte bundle header offset, then
//! a 32-byte signature. `dotnet publish` writes the offset only for a single-file bundle, and
//! leaves it zero otherwise. The search streams the file in chunks, so memory stays bounded
//! however large the file, and stops at the first signature, as the SDK's
//! `Bundler.IsBundle` does.
//!
//! The same pass can look for the muxer's usage line, which identifies it where there's no
//! PE version resource to ask.

use crate::source::Source;
use std::hint::black_box;

/// The bundle signature: SHA-256 of ".net core bundle".
///
/// From `src/native/corehost/apphost/bundle_marker.c` in dotnet/runtime, and the SDK's
/// `Bundler.BundleHeaderPlaceholder`, which writes the offset in front of it.
const SIGNATURE: [u8; 32] = [
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, //
    0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32, //
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, //
    0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae, //
];

/// The bundle header offset: a little-endian `int64_t` right before the signature.
const OFFSET_LEN: usize = size_of::<i64>();

/// The whole placeholder: the offset, then the signature.
const PLACEHOLDER_LEN: usize = OFFSET_LEN + SIGNATURE.len();

/// The first line the muxer prints when run with no arguments.
///
/// From the muxer's `exe_start` in dotnet/runtime: `src/native/corehost/corehost.cpp` on
/// release/6.0 through release/10.0, and `src/native/corehost/dotnet/dotnet.cpp` on main.
/// The apphost's build leaves it out. `_X()` makes it UTF-8 outside Windows.
const USAGE: [u8; 35] = *b"Usage: dotnet [path-to-application]";

// TRICK: a `const` is copied into the code that uses it at run time, and never emitted on its
// own. Only the masked copies are used at run time, unmasked behind `black_box` so the
// optimizer can't fold them back. Without this, every binary that links dotnot, mirrord
// included, would carry both needles, and classify as an apphost.
const MASK: u8 = 0x5a;
const MASKED_SIGNATURE: [u8; SIGNATURE.len()] = mask(SIGNATURE);
const MASKED_USAGE: [u8; USAGE.len()] = mask(USAGE);

const fn mask<const N: usize>(mut bytes: [u8; N]) -> [u8; N] {
    let mut index = 0;
    while index < N {
        bytes[index] ^= MASK;
        index += 1;
    }
    bytes
}

fn unmask<const N: usize>(masked: [u8; N]) -> [u8; N] {
    let mask = black_box(MASK);
    masked.map(|byte| byte ^ mask)
}

/// How much of the file is read at a time.
const CHUNK_LEN: usize = 64 * 1024;

/// What the search found in the file.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Found {
    /// The bundle header offset in front of the first signature, if the file has one.
    pub(crate) bundle_header_offset: Option<i64>,
    /// The muxer's usage line is in the file, when the search looked for it.
    pub(crate) usage: bool,
}

/// Searches the whole source for the bundle marker, stopping at the first one.
///
/// With `find_usage`, it also looks for the muxer's usage line on the way.
pub(crate) fn scan<S: Source>(source: &mut S, find_usage: bool) -> Result<Found, S::Error> {
    scan_in_chunks(source, find_usage, CHUNK_LEN)
}

fn scan_in_chunks<S: Source>(
    source: &mut S,
    find_usage: bool,
    chunk_len: usize,
) -> Result<Found, S::Error> {
    let signature = unmask(MASKED_SIGNATURE);
    let usage = unmask(MASKED_USAGE);
    // The window is the tail of the chunks so far, then the new chunk. The tail is one byte
    // short of the longer needle, so a needle split across chunks is still seen whole.
    let tail_len = PLACEHOLDER_LEN.max(USAGE.len()) - 1;
    let mut window = Vec::with_capacity(tail_len + chunk_len);
    let mut offset = 0u64;
    let mut found = Found::default();
    loop {
        let tail = window.len();
        window.resize(tail + chunk_len, 0);
        let read = source.read_at(offset, &mut window[tail..])?;
        window.truncate(tail + read);
        if read == 0 {
            return Ok(found);
        }
        offset += read as u64;

        if let Some(header_offset) = first_placeholder(&window, &signature) {
            found.bundle_header_offset = Some(header_offset);
            return Ok(found);
        }
        if find_usage && !found.usage {
            found.usage = window
                .windows(usage.len())
                .any(|line| line[0] == usage[0] && line == usage);
        }
        window.drain(..window.len().saturating_sub(tail_len));
    }
}

/// The bundle header offset of the first signature with a whole offset in front of it.
///
/// A signature in the first 8 bytes of the file has no room for its offset, so it isn't an
/// apphost's placeholder.
fn first_placeholder(window: &[u8], signature: &[u8; SIGNATURE.len()]) -> Option<i64> {
    window.windows(PLACEHOLDER_LEN).find_map(|placeholder| {
        let (header_offset, rest) = placeholder.split_first_chunk::<OFFSET_LEN>()?;
        // Comparing the first byte alone skips most windows without a call to `memcmp`.
        (rest[0] == signature[0] && rest == signature).then(|| i64::from_le_bytes(*header_offset))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_OFFSET: i64 = 0x1122_3344_5566_7788;

    /// A file of filler with one placeholder at `at`.
    fn file_with_placeholder(len: usize, at: usize, header_offset: i64) -> Vec<u8> {
        let mut file = vec![0xcc; len];
        file[at..at + OFFSET_LEN].copy_from_slice(&header_offset.to_le_bytes());
        file[at + OFFSET_LEN..at + PLACEHOLDER_LEN].copy_from_slice(&unmask(MASKED_SIGNATURE));
        file
    }

    /// The chunk sizes around the placeholder's own length are where a split goes wrong.
    #[test]
    fn a_placeholder_split_across_chunks_is_found_at_every_position() {
        for chunk_len in [
            1,
            2,
            7,
            PLACEHOLDER_LEN - 1,
            PLACEHOLDER_LEN,
            PLACEHOLDER_LEN + 1,
            64,
        ] {
            for at in 0..=120 {
                let file = file_with_placeholder(at + PLACEHOLDER_LEN + 40, at, HEADER_OFFSET);
                let found = scan_in_chunks(&mut file.as_slice(), false, chunk_len)
                    .expect("bytes always read");
                assert_eq!(
                    found.bundle_header_offset,
                    Some(HEADER_OFFSET),
                    "the placeholder at {at} must be found whole with {chunk_len}-byte chunks"
                );
            }
        }
    }

    #[test]
    fn the_first_placeholder_wins_like_the_sdk() {
        let mut file = file_with_placeholder(300, 10, 0);
        let second = file_with_placeholder(300, 200, HEADER_OFFSET);
        file[200..200 + PLACEHOLDER_LEN].copy_from_slice(&second[200..200 + PLACEHOLDER_LEN]);

        let found = scan_in_chunks(&mut file.as_slice(), false, 64).expect("bytes always read");
        assert_eq!(
            found.bundle_header_offset,
            Some(0),
            "the SDK patches and reads the first one"
        );
    }

    #[test]
    fn a_usage_line_split_across_chunks_is_found_at_every_position() {
        for chunk_len in [1, 2, 7, USAGE.len() - 1, USAGE.len(), USAGE.len() + 1, 64] {
            for at in 0..=120 {
                let mut file = vec![0xcc; at + USAGE.len() + 40];
                file[at..at + USAGE.len()].copy_from_slice(&unmask(MASKED_USAGE));
                let found = scan_in_chunks(&mut file.as_slice(), true, chunk_len)
                    .expect("bytes always read");
                assert!(
                    found.usage,
                    "the usage line at {at} must be found whole with {chunk_len}-byte chunks"
                );
            }
        }
    }

    /// The mask only works if the code that unmasks it gives back the needles themselves.
    #[test]
    fn the_masked_needles_unmask_to_the_needles() {
        assert_eq!(unmask(MASKED_USAGE), USAGE);
        assert_eq!(unmask(MASKED_SIGNATURE), SIGNATURE);
        assert_ne!(
            MASKED_SIGNATURE, SIGNATURE,
            "the mask must change the stored bytes"
        );
    }
}
