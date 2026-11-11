//! Helpers the test files share.

#![allow(dead_code)] // Each test file uses its own subset.

use std::path::PathBuf;

/// A fresh, empty directory under Cargo's per-target scratch space, for one test.
pub fn scratch_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the target scratch dir is writable");
    dir
}

/// Where the hand-built PE puts its NT headers.
pub const NT_OFFSET: usize = 0x40;
/// The fixed fields of a PE32 optional header, before its data directories.
pub const PE32_FIXED: usize = 96;
/// The fixed fields of a PE32+ optional header, before its data directories.
pub const PE32_PLUS_FIXED: usize = 112;
/// The COM descriptor (CLR header) data directory's index.
pub const CLR_DIRECTORY: usize = 14;

/// A minimal PE image to build edge cases from: a DOS header, the NT headers with all 16
/// data directories written out, then the section table.
pub struct Pe {
    /// 0x10b for PE32, 0x20b for PE32+.
    pub magic: u16,
    pub directory_count: u32,
    /// The CLR header directory: its address, then its size.
    pub clr: (u32, u32),
    /// `SizeOfOptionalHeader`, when it differs from the header actually written.
    pub optional_len: Option<u16>,
    /// `NumberOfSections`. The table itself is never written, so any count is cut short.
    pub section_count: u16,
}

impl Pe {
    /// A native PE32+ image: no CLR header.
    pub fn native() -> Self {
        Self {
            magic: 0x20b,
            directory_count: 16,
            clr: (0, 0),
            optional_len: None,
            section_count: 0,
        }
    }

    /// A managed PE32+ image: a CLR header, like an IL `.dll`.
    pub fn managed() -> Self {
        Self {
            clr: (0x2008, 0x48),
            ..Self::native()
        }
    }

    fn fixed_len(&self) -> usize {
        if self.magic == 0x10b {
            PE32_FIXED
        } else {
            PE32_PLUS_FIXED
        }
    }

    /// The `SizeOfOptionalHeader` the image declares.
    pub fn declared_optional_len(&self) -> u16 {
        self.optional_len
            .unwrap_or((self.fixed_len() + 16 * 8) as u16)
    }

    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; NT_OFFSET];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&(NT_OFFSET as u32).to_le_bytes());

        bytes.extend_from_slice(b"PE\0\0");
        let mut file_header = [0u8; 20];
        file_header[..2].copy_from_slice(&0x8664u16.to_le_bytes());
        file_header[2..4].copy_from_slice(&self.section_count.to_le_bytes());
        file_header[16..18].copy_from_slice(&self.declared_optional_len().to_le_bytes());
        bytes.extend_from_slice(&file_header);

        let fixed = self.fixed_len();
        let written = (fixed + 16 * 8).max(self.declared_optional_len().into());
        let mut optional = vec![0u8; written];
        optional[..2].copy_from_slice(&self.magic.to_le_bytes());
        optional[fixed - 4..fixed].copy_from_slice(&self.directory_count.to_le_bytes());
        let clr = fixed + CLR_DIRECTORY * 8;
        optional[clr..clr + 4].copy_from_slice(&self.clr.0.to_le_bytes());
        optional[clr + 4..clr + 8].copy_from_slice(&self.clr.1.to_le_bytes());
        bytes.extend_from_slice(&optional);
        bytes
    }
}

/// Deterministic noise: the same seed gives the same bytes on every run, so a failure
/// reproduces.
pub struct Garbage(u64);

impl Garbage {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next pseudo-random value (SplitMix64).
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}
