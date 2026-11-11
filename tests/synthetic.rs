//! Hand-built inputs for each rule, its edges, and malformed input.
//!
//! The marker bytes here are a second copy, typed from dotnet/runtime's source, so a typo in
//! the crate's own copy fails these tests.

mod common;

use common::Garbage;
use dotnot::{DotnetKind, Error, classify, classify_bytes};

/// The bundle signature, from `src/native/corehost/apphost/bundle_marker.c` in dotnet/runtime.
const SIGNATURE: [u8; 32] = [
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, //
    0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32, //
    0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae, 0x33, 0x18, //
    0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae, //
];

/// Filler, then the 8-byte bundle header offset and the signature at `at`, then more filler.
fn with_placeholder(at: usize, header_offset: i64) -> Vec<u8> {
    let mut bytes = vec![0xcc; at];
    bytes.extend_from_slice(&header_offset.to_le_bytes());
    bytes.extend_from_slice(&SIGNATURE);
    bytes.extend_from_slice(&[0xcc; 64]);
    bytes
}

fn classified(bytes: &[u8]) -> DotnetKind {
    classify_bytes(bytes).expect("these inputs are not PE files, so they can't be malformed")
}

#[test]
fn a_placeholder_with_a_zero_offset_is_an_apphost_that_is_not_single_file() {
    assert_eq!(
        classified(&with_placeholder(100, 0)),
        DotnetKind::Apphost { single_file: false }
    );
}

#[test]
fn a_placeholder_with_a_nonzero_offset_is_a_single_file_bundle() {
    assert_eq!(
        classified(&with_placeholder(100, 168_741)),
        DotnetKind::Apphost { single_file: true }
    );
}

/// The runtime's own rule is `bundle_header_offset != 0` on an `int64_t`, so any nonzero
/// value counts, even one no real bundle has.
#[test]
fn a_negative_offset_is_still_a_single_file_bundle_like_the_runtime_reads_it() {
    assert_eq!(
        classified(&with_placeholder(100, -1)),
        DotnetKind::Apphost { single_file: true }
    );
}

#[test]
fn a_signature_with_no_room_for_its_offset_is_not_a_placeholder() {
    for at in 0..8 {
        let mut bytes = vec![0xcc; at];
        bytes.extend_from_slice(&SIGNATURE);
        bytes.extend_from_slice(&[0xcc; 64]);
        assert_eq!(
            classified(&bytes),
            DotnetKind::NotDotnet,
            "a signature at {at} has only {at} bytes before it, not 8"
        );
    }
}

#[test]
fn a_signature_cut_short_by_the_end_of_the_file_is_not_a_placeholder() {
    let mut bytes = with_placeholder(100, 0);
    bytes.truncate(100 + 8 + SIGNATURE.len() - 1);
    assert_eq!(classified(&bytes), DotnetKind::NotDotnet);
}

#[test]
fn an_empty_file_is_not_dotnet() {
    assert_eq!(classified(&[]), DotnetKind::NotDotnet);
}

#[test]
fn garbage_is_not_dotnet() {
    let mut garbage = Garbage::new(0x5eed);
    for len in [1, 2, 3, 4, 63, 64, 65, 4096, 100_000] {
        assert_eq!(
            classified(&garbage.bytes(len)),
            DotnetKind::NotDotnet,
            "{len} bytes of noise carry no .NET signal"
        );
    }
}

/// `classify` reads files in 64 KiB chunks: a placeholder on either side of a chunk boundary,
/// or across it, must be found as it is in memory.
#[test]
fn a_file_with_a_placeholder_across_a_read_boundary_is_found_like_the_bytes() {
    const CHUNK: usize = 64 * 1024;
    let dir = common::scratch_dir("placeholder_across_a_read_boundary");
    for at in [
        CHUNK - 41,
        CHUNK - 40,
        CHUNK - 20,
        CHUNK - 8,
        CHUNK - 1,
        CHUNK,
        3 * CHUNK - 13,
    ] {
        let bytes = with_placeholder(at, 168_741);
        let path = dir.join(format!("at-{at}.bin"));
        std::fs::write(&path, &bytes).expect("the scratch dir is writable");

        assert_eq!(
            classify(&path).expect("the file was just written"),
            DotnetKind::Apphost { single_file: true },
            "the placeholder at {at} spans the chunk boundary at {CHUNK}"
        );
    }
}

#[test]
fn a_missing_file_fails_to_open_and_names_the_path() {
    let path = common::scratch_dir("missing_file").join("not-here.exe");
    let error = classify(&path).expect_err("the file doesn't exist");
    assert!(
        matches!(&error, Error::Open { path: reported, .. } if *reported == path),
        "expected Error::Open for {}, got {error:?}",
        path.display()
    );
}
