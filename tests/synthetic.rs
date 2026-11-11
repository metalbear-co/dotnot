//! Hand-built inputs for each rule, its edges, and malformed input.
//!
//! The marker bytes here are a second copy, typed from dotnet/runtime's source, so a typo in
//! the crate's own copy fails these tests.

mod common;

use common::{Garbage, NT_OFFSET, Pe};
use dotnot::{DotnetKind, Error, PeError, classify, classify_bytes};

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

fn classified_pe(pe: &Pe) -> DotnetKind {
    classify_bytes(&pe.bytes()).expect("the hand-built headers are whole")
}

#[test]
fn a_pe32_plus_with_a_clr_header_is_a_framework_assembly() {
    assert_eq!(classified_pe(&Pe::managed()), DotnetKind::FrameworkAssembly);
}

#[test]
fn a_pe32_with_a_clr_header_is_a_framework_assembly() {
    let pe = Pe {
        magic: 0x10b,
        ..Pe::managed()
    };
    assert_eq!(classified_pe(&pe), DotnetKind::FrameworkAssembly);
}

#[test]
fn a_pe_without_a_clr_header_or_a_marker_is_not_dotnet() {
    assert_eq!(classified_pe(&Pe::native()), DotnetKind::NotDotnet);
}

#[test]
fn half_a_clr_directory_is_no_clr_header() {
    for clr in [(0x2008, 0), (0, 0x48)] {
        let pe = Pe {
            clr,
            ..Pe::native()
        };
        assert_eq!(
            classified_pe(&pe),
            DotnetKind::NotDotnet,
            "the directory {clr:x?} needs both an address and a size"
        );
    }
}

/// The CLR header is directory 14, so it exists only when NumberOfRvaAndSizes is at least 15.
#[test]
fn a_clr_directory_past_number_of_rva_and_sizes_is_not_read() {
    let pe = Pe {
        directory_count: 14,
        ..Pe::managed()
    };
    assert_eq!(classified_pe(&pe), DotnetKind::NotDotnet);
}

#[test]
fn a_clr_directory_past_the_optional_header_is_not_read() {
    let header_without_it = (common::PE32_PLUS_FIXED + common::CLR_DIRECTORY * 8) as u16;
    let pe = Pe {
        optional_len: Some(header_without_it),
        ..Pe::managed()
    };
    assert_eq!(classified_pe(&pe), DotnetKind::NotDotnet);
}

#[test]
fn a_native_pe_with_the_marker_is_an_apphost() {
    let mut bytes = Pe::native().bytes();
    bytes.extend_from_slice(&with_placeholder(16, 0));
    assert_eq!(
        classify_bytes(&bytes).expect("the headers are whole"),
        DotnetKind::Apphost { single_file: false }
    );
}

/// An apphost is native, so a CLR header answers without reading the rest of the file.
#[test]
fn a_clr_header_settles_it_before_the_marker_scan() {
    let mut bytes = Pe::managed().bytes();
    bytes.extend_from_slice(&with_placeholder(16, 0));
    assert_eq!(
        classify_bytes(&bytes).expect("the headers are whole"),
        DotnetKind::FrameworkAssembly
    );
}

/// An `MZ` file with no `PE\0\0` where its header points is a DOS program, not a broken PE.
#[test]
fn an_mz_file_without_a_pe_signature_is_not_dotnet() {
    let mut beyond_the_end = Pe::native().bytes();
    beyond_the_end.truncate(NT_OFFSET);
    beyond_the_end[0x3c..0x40].copy_from_slice(&0x1000u32.to_le_bytes());

    let mut not_pe = Pe::native().bytes();
    not_pe[NT_OFFSET..NT_OFFSET + 4].copy_from_slice(b"NE\0\0");

    for (case, bytes) in [
        ("e_lfanew past the end", beyond_the_end),
        ("an NE signature", not_pe),
    ] {
        assert_eq!(
            classify_bytes(&bytes).expect("a DOS program isn't malformed"),
            DotnetKind::NotDotnet,
            "{case}"
        );
    }
}

#[test]
fn malformed_headers_name_what_is_wrong() {
    let whole = Pe::native().bytes();
    let declared = Pe::native().declared_optional_len();
    let unknown_magic = Pe {
        magic: 0x107,
        ..Pe::native()
    };
    let one_byte_optional = Pe {
        optional_len: Some(1),
        ..Pe::native()
    };
    let no_fixed_fields = Pe {
        optional_len: Some(50),
        ..Pe::native()
    };
    let one_section = Pe {
        section_count: 1,
        ..Pe::native()
    };
    let nt = NT_OFFSET as u64;

    let cases: [(&str, Vec<u8>, PeError); 7] = [
        (
            "cut inside the DOS header",
            whole[..10].to_vec(),
            PeError::TruncatedDosHeader,
        ),
        (
            "cut inside the file header",
            whole[..NT_OFFSET + 10].to_vec(),
            PeError::TruncatedNtHeaders { offset: nt },
        ),
        (
            "cut inside the optional header",
            whole[..NT_OFFSET + 24 + 50].to_vec(),
            PeError::TruncatedNtHeaders { offset: nt },
        ),
        (
            "a ROM image's magic",
            unknown_magic.bytes(),
            PeError::UnknownOptionalHeaderMagic { magic: 0x107 },
        ),
        (
            "a 1-byte optional header",
            one_byte_optional.bytes(),
            PeError::OptionalHeaderTooSmall { size: 1 },
        ),
        (
            "an optional header without its fixed fields",
            no_fixed_fields.bytes(),
            PeError::OptionalHeaderTooSmall { size: 50 },
        ),
        (
            "a section table past the end",
            one_section.bytes(),
            PeError::TruncatedSectionTable {
                offset: nt + 24 + u64::from(declared),
            },
        ),
    ];
    for (case, bytes, expected) in cases {
        match classify_bytes(&bytes) {
            Err(Error::MalformedPe(error)) => assert_eq!(error, expected, "{case}"),
            other => panic!("{case}: expected Error::MalformedPe({expected:?}), got {other:?}"),
        }
    }
}

/// Every prefix of a PE is either a whole decision or a typed error, never a panic or a
/// .NET answer the bytes don't support.
#[test]
fn every_truncation_of_a_pe_decides_or_reports_malformed_headers() {
    let bytes = Pe::managed().bytes();
    for len in 0..=bytes.len() {
        match classify_bytes(&bytes[..len]) {
            Ok(DotnetKind::NotDotnet | DotnetKind::FrameworkAssembly)
            | Err(Error::MalformedPe(_)) => {}
            other => panic!("the first {len} bytes gave {other:?}"),
        }
    }
}

/// Noise written over the headers can make any answer, but never a panic.
#[test]
fn pe_headers_full_of_noise_never_panic() {
    let mut garbage = Garbage::new(0xbad_c0de);
    let pristine = Pe::managed().bytes();
    for _ in 0..5_000 {
        let mut bytes = pristine.clone();
        for _ in 0..1 + garbage.next() % 8 {
            let at = (garbage.next() % bytes.len() as u64) as usize;
            bytes[at] = garbage.next() as u8;
        }
        let _ = classify_bytes(&bytes);
    }
}
