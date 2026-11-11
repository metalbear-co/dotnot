//! The PE facts dotnot needs: a CLR header, and the muxer's version resource.
//!
//! Only the headers and the resource directory are read. pelite's `PeFile` needs the whole
//! image in memory, so the headers are decoded here into pelite's structures, and only the
//! resource bytes go through pelite's resource parser.

use crate::{
    error::PeError,
    source::{Failure, Source},
};
use dataview::{DataView, Pod};
use pelite::{image::*, resources::Resources};

/// The muxer's `FileDescription`, from the `dotnet` item in dotnet/runtime's
/// `src/native/corehost/corehost.proj`.
///
/// Its other hosts differ: hostfxr is `.NET Host Resolver - <version>`, for example.
const MUXER_DESCRIPTION: &str = ".NET Host";

/// The most resource bytes read.
///
/// The muxer's resources are its icon and its version, far below this. The cap only bounds
/// what a hostile header can make dotnot allocate.
const MAX_RESOURCES_LEN: u32 = 1 << 20;

/// A data directory the image doesn't have.
const NO_DIRECTORY: IMAGE_DATA_DIRECTORY = IMAGE_DATA_DIRECTORY {
    VirtualAddress: 0,
    Size: 0,
};

/// The parts of a PE's headers the decision needs.
pub(crate) struct Headers {
    clr: IMAGE_DATA_DIRECTORY,
    resources: IMAGE_DATA_DIRECTORY,
    sections: Vec<IMAGE_SECTION_HEADER>,
}

impl Headers {
    /// Reads the headers of a file that starts with `MZ`.
    ///
    /// # Returns
    ///
    /// * `Ok(None)` - the file doesn't start with `MZ`, or has no `PE\0\0` where its DOS
    ///   header points: it isn't a PE image, so none of the PE rules apply.
    /// * `Err(Failure::Pe(_))` - it is a PE image, with headers cut short or unknown.
    pub(crate) fn read<S: Source>(source: &mut S) -> Result<Option<Self>, Failure<S::Error>> {
        let mut dos = [0u8; size_of::<IMAGE_DOS_HEADER>()];
        let read = source.read_at(0, &mut dos).map_err(Failure::Read)?;
        if read < 2 || u16::from_le_bytes([dos[0], dos[1]]) != IMAGE_DOS_SIGNATURE {
            return Ok(None);
        }
        let dos: IMAGE_DOS_HEADER = DataView::from(&dos[..read])
            .try_read(0)
            .ok_or(PeError::TruncatedDosHeader)?;

        // A DOS program has no PE signature at e_lfanew, or none at all past the file's end.
        let nt_offset = u64::from(dos.e_lfanew);
        match read_pod::<u32, S>(source, nt_offset)? {
            Some(IMAGE_NT_HEADERS_SIGNATURE) => {}
            _ => return Ok(None),
        }
        let truncated = PeError::TruncatedNtHeaders { offset: nt_offset };
        let file_offset = nt_offset + size_of::<u32>() as u64;
        let file: IMAGE_FILE_HEADER = read_pod(source, file_offset)?.ok_or(truncated)?;

        let optional_offset = file_offset + size_of::<IMAGE_FILE_HEADER>() as u64;
        let optional_len = file.SizeOfOptionalHeader;
        let optional =
            read_bytes(source, optional_offset, optional_len.into())?.ok_or(truncated)?;
        let optional = DataView::from(optional.as_slice());
        let too_small = PeError::OptionalHeaderTooSmall { size: optional_len };
        let magic: u16 = optional.try_read(0).ok_or(too_small)?;
        let (directory_count, directories_at) = match magic {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => (
                optional
                    .try_read::<IMAGE_OPTIONAL_HEADER32>(0)
                    .map(|header| header.NumberOfRvaAndSizes),
                size_of::<IMAGE_OPTIONAL_HEADER32>(),
            ),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => (
                optional
                    .try_read::<IMAGE_OPTIONAL_HEADER64>(0)
                    .map(|header| header.NumberOfRvaAndSizes),
                size_of::<IMAGE_OPTIONAL_HEADER64>(),
            ),
            magic => return Err(PeError::UnknownOptionalHeaderMagic { magic }.into()),
        };
        let directory_count = directory_count.ok_or(too_small)?;
        // A directory exists only below NumberOfRvaAndSizes, and inside the optional header.
        let directory = |index: usize| -> IMAGE_DATA_DIRECTORY {
            let at = directories_at + index * size_of::<IMAGE_DATA_DIRECTORY>();
            (index < directory_count as usize)
                .then(|| optional.try_read(at))
                .flatten()
                .unwrap_or(NO_DIRECTORY)
        };

        let sections_offset = optional_offset + u64::from(optional_len);
        let section_count = usize::from(file.NumberOfSections);
        let table = read_bytes(
            source,
            sections_offset,
            section_count * size_of::<IMAGE_SECTION_HEADER>(),
        )?
        .ok_or(PeError::TruncatedSectionTable {
            offset: sections_offset,
        })?;
        let table = DataView::from(table.as_slice());
        let sections = (0..section_count)
            .filter_map(|index| table.try_read(index * size_of::<IMAGE_SECTION_HEADER>()))
            .collect();

        Ok(Some(Self {
            clr: directory(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR),
            resources: directory(IMAGE_DIRECTORY_ENTRY_RESOURCE),
            sections,
        }))
    }

    /// The image has a CLR header: it's managed code, which the CLR loads.
    pub(crate) fn has_clr_header(&self) -> bool {
        self.clr.VirtualAddress != 0 && self.clr.Size != 0
    }

    /// The image's version resource says it's the muxer.
    ///
    /// Missing, unreachable or malformed resources say nothing, so they aren't the muxer.
    pub(crate) fn is_muxer<S: Source>(&self, source: &mut S) -> Result<bool, S::Error> {
        let Some((offset, len)) = self.resources_in_file() else {
            return Ok(false);
        };
        // pelite reads the resource tables in place, so they need the alignment a PE mapping
        // gives them; a `u64` buffer has it, where caller bytes or a `Vec<u8>` may not.
        let mut buffer = vec![0u64; len.div_ceil(size_of::<u64>())];
        let bytes = &mut dataview::bytes_mut(buffer.as_mut_slice())[..len];
        let read = source.read_at(offset, bytes)?;

        let resources = Resources::new(&bytes[..read], &self.resources);
        let Ok(version) = resources.version_info() else {
            return Ok(false);
        };
        Ok(version.translation().iter().any(|&language| {
            version.value(language, "FileDescription").as_deref() == Some(MUXER_DESCRIPTION)
        }))
    }

    /// Where the resource directory lies in the file, and how much of it to read.
    fn resources_in_file(&self) -> Option<(u64, usize)> {
        let rva = self.resources.VirtualAddress;
        if rva == 0 || self.resources.Size == 0 {
            return None;
        }
        let section = self.sections.iter().find(|section| {
            rva >= section.VirtualAddress && rva - section.VirtualAddress < section.SizeOfRawData
        })?;
        let into_section = rva - section.VirtualAddress;
        let len = self
            .resources
            .Size
            .min(section.SizeOfRawData - into_section)
            .min(MAX_RESOURCES_LEN);
        let offset = u64::from(section.PointerToRawData) + u64::from(into_section);
        Some((offset, len as usize))
    }
}

/// Reads exactly `len` bytes at `offset`, or `None` when the source ends first.
fn read_bytes<S: Source>(
    source: &mut S,
    offset: u64,
    len: usize,
) -> Result<Option<Vec<u8>>, Failure<S::Error>> {
    let mut bytes = vec![0; len];
    let read = source.read_at(offset, &mut bytes).map_err(Failure::Read)?;
    Ok((read == len).then_some(bytes))
}

/// Reads one header structure at `offset`, or `None` when the source ends first.
fn read_pod<T: Pod, S: Source>(
    source: &mut S,
    offset: u64,
) -> Result<Option<T>, Failure<S::Error>> {
    Ok(read_bytes(source, offset, size_of::<T>())?
        .and_then(|bytes| DataView::from(bytes.as_slice()).try_read(0)))
}
