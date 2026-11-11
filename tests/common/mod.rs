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
