# dotnot

**dotnot tells whether an executable is .NET, or not.**

mirrord's `exec` uses it to pick how to hold a service's root process for a debugger:

- **A .NET (Core / 5+) program** is held at the runtime's own startup pause, through `DOTNET_DiagnosticPorts`.
- **A .NET Framework program, or a native one,** is held at process creation.

It reads only what the decision needs, never the whole file into memory. It has no `unsafe` code, and works the same on Windows, Linux and macOS.

## Quick start

```rust,no_run
use dotnot::DotnetKind;
use std::path::Path;

/// The hold mirrord describes: the runtime's pause for .NET (Core / 5+), creation otherwise.
fn holds_at_runtime_pause(program: &Path) -> Result<bool, dotnot::Error> {
    Ok(match dotnot::classify(program)? {
        DotnetKind::Apphost { .. } | DotnetKind::Muxer => true,
        DotnetKind::FrameworkAssembly | DotnetKind::NotDotnet => false,
    })
}
```

`classify_bytes(&bytes)` decides the same way for bytes already in memory.

## How it decides

**The first rule that matches wins:**

| # | The file | dotnot says |
|---|---|---|
| 1 | is a PE with a CLR header | `FrameworkAssembly` |
| 2 | holds the apphost's bundle marker | `Apphost { single_file }`, where `single_file` is "the bundle header offset is nonzero" |
| 3 | is a PE whose version resource has `FileDescription` ".NET Host" | `Muxer` |
| 4 | is ELF or Mach-O, and holds the muxer's usage line | `Muxer` |
| 5 | is anything else | `NotDotnet` |

Rule 1 comes first because an apphost is native code. A CLR header settles the answer from the headers alone, so a large managed assembly is never scanned.

**These facts back the rules,** each from a run on Windows with SDK 10.0.401:

| Binary | Bundle marker | CLR header | Version resource | dotnot says |
|---|---|---|---|---|
| an apphost, like `Shop.Orders.Api.exe` | present; the offset before it is 0 | no | OriginalFilename `Shop.Orders.Api.dll` | `Apphost { single_file: false }` |
| a `PublishSingleFile` apphost | present; the offset is nonzero | no | | `Apphost { single_file: true }` |
| the app's IL `.dll`, like `Shop.Orders.Api.dll` | absent | yes | | `FrameworkAssembly` |
| `dotnet.exe`, the muxer behind `dotnet x.dll` and `dotnet run` (x64 and x86) | absent | no | FileDescription and OriginalFilename ".NET Host", ProductName ".NET" | `Muxer` |
| `RegAsm.exe`, `InstallUtil.exe` (.NET Framework) | absent | yes | | `FrameworkAssembly` |
| `notepad.exe`, `mirrord.exe` (Rust), `csc.exe` (native today) | absent | no | | `NotDotnet` |

<details>
<summary>Where each signal comes from</summary>

- **The bundle marker** is a 40-byte placeholder in every apphost: an 8-byte little-endian bundle header offset, then a 32-byte signature (SHA-256 of ".net core bundle"). It's defined in dotnet/runtime's `src/native/corehost/apphost/bundle_marker.c`. The runtime's rule is `bundle_header_offset != 0`.
- **The SDK reads it the same way.** `Bundler.IsBundle` takes the first signature in the file and reads the `int64` before it. `dotnet publish` writes that offset only for a single-file bundle.
- **The CLR header** is the COM descriptor data directory, index 14. It counts only when it's inside `NumberOfRvaAndSizes` and the optional header, with a nonzero address and size.
- **".NET Host"** is the `FileDescription` dotnet/runtime's `src/native/corehost/corehost.proj` gives the `dotnet` host alone, on release/6.0, release/8.0 and main. hostfxr is `.NET Host Resolver - <version>`, for example.
- **The usage line** is `Usage: dotnet [path-to-application]`. The muxer prints it when run with no arguments. Only the muxer's build compiles it in: `corehost.cpp` keeps it out of `FEATURE_APPHOST` on release/6.0 through release/10.0, and main moved the muxer into its own `dotnet/dotnet.cpp`. It's UTF-8 outside Windows.

</details>

> An IL-only `.dll` has a CLR header too, so it's `FrameworkAssembly`. It never starts on its own, though: its apphost or the muxer starts it, and those are what mirrord classifies.

## API

| Item | What it is |
|---|---|
| `classify(path: impl AsRef<Path>) -> Result<DotnetKind, Error>` | Classifies a file, read in pieces |
| `classify_bytes(bytes: &[u8]) -> Result<DotnetKind, Error>` | Classifies bytes already in memory |
| `DotnetKind` | `Apphost { single_file: bool }`, `Muxer`, `FrameworkAssembly` or `NotDotnet` |
| `Error` | `Open` and `Read` carry the path and the I/O error; `MalformedPe` carries a `PeError` |
| `PeError` | What's wrong with a PE's headers: cut short, or an unknown optional header magic |

**A file that isn't an executable dotnot knows is not an error.** It's `NotDotnet`. So is an `MZ` file without a PE signature, which is a DOS program.

**Broken resources are not an error either.** They can't say the file is the muxer, so the answer stands.

`DotnetKind` is deliberately not `#[non_exhaustive]`. A new kind should break mirrord's `match` at compile time, not fall into a wildcard arm.

## What it reads

**dotnot streams the file in 64 KiB chunks; it doesn't memory-map it.**

| Step | What's read |
|---|---|
| PE headers | the DOS header, the NT headers and the section table |
| Rule 1 | nothing more: the CLR header is in the headers |
| Rules 2 and 4 | one pass from the start, stopping at the first marker; the whole file only when there's none |
| Rule 3 | the resource directory, capped at 1 MiB |

Why streaming, not a memory map:

- **No `unsafe`.** A map is undefined behavior if another process changes the file under it, which is why `memmap2::Mmap::map` is `unsafe`. dotnot forbids `unsafe` code.
- **No new dependency.** pelite's own map needs its `mmap` feature, and `PeFile` wants the whole image anyway.
- **Bounded memory, early exit.** The window is one chunk plus 39 bytes. A self-contained single-file host carries its marker about 8 MB in; the bundle after it, often much larger, is never read.

**A native binary has no marker, so it's read to the end.** That's the costly case, and the common one for mirrord.

> Recorded runs, release build of dotnot: the 8 MB `singlefilehost.exe` from the SDK's host pack, about 6 ms. A 132 MB debug `mirrord.exe`, about 73 ms from the OS cache, and 1.4 s on a cold first read.

**dotnot itself never holds either needle in plain form.** Both are stored masked, and unmasked behind `std::hint::black_box`. Otherwise every binary linking dotnot, mirrord included, would classify as an apphost.

## Cross-platform status

**Nothing is OS-gated.** The code uses only `std` file reads, and each rule checks the file's format, not the host's. Classifying a Windows PE on Linux works.

| | Windows | Linux | macOS |
|---|---|---|---|
| Builds | yes (run) | not checked: the target isn't installed here | not checked: the target isn't installed here |
| Apphost, single-file | verified (run) | the same format-agnostic bytes; unverified | the same format-agnostic bytes; unverified |
| Muxer | version resource, verified (run) | usage line, from source; unverified | usage line, from source; unverified |
| CLR header | verified (run) | an IL `.dll` is a PE on every OS | an IL `.dll` is a PE on every OS |

**The Unix muxer rule is a known gap until it runs on Linux and macOS.** The evidence so far:

- **Source:** the usage line is compiled into the muxer on release/6.0, release/8.0, release/10.0 and main.
- **The same literal on Windows:** `dotnet.exe` holds it once, as UTF-16, and none of the 12 apphost and single-file host templates in the SDK's win-arm64, win-x64 and win-x86 host packs holds it (run).

The real-binary tests run the muxer, apphost and single-file cases on whichever platform runs them. A Linux or macOS machine with the SDK verifies those rules with a plain `cargo test`.

> On Linux, `dotnet` on PATH may be a symlink, which is fine, or a wrapper script, which classifies as `NotDotnet`. Pass the muxer's real path.

## Testing

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

- **`tests/synthetic.rs`:** hand-built inputs for each rule, its edges, truncation and noise.
- **`tests/real_binaries.rs`:** a table of real binaries. The muxer on PATH, plus an apphost, a single-file publish and an IL `.dll` built from `tests/fixtures/hello`. On Windows, also RegAsm, InstallUtil, notepad and csc.
- **The fixture builds offline,** in `target/tmp`: an empty `--source` feed, and `--disable-build-servers`, so nothing downloads and no compiler server outlives the run.
- **It needs only the packs inside the SDK,** never a warm NuGet cache. The single-file publish is framework-dependent, and the fixture turns off the single-file analyzer, which would pull in the ILLink and runtime packs. To see the run as a fresh machine does, point `NUGET_PACKAGES` at an empty folder.
- **Without `dotnet` on PATH,** the .NET cases skip and say so. Set `DOTNOT_REQUIRE_DOTNET=1` to make that a failure, as CI should.

## Layout

- `src/lib.rs`: `classify`, `classify_bytes`, and the decision order.
- `src/kind.rs`: `DotnetKind`.
- `src/error.rs`: `Error` and `PeError`.
- `src/source.rs`: reading at an offset from a file or from bytes.
- `src/scan.rs`: the streaming search for the bundle marker and the usage line.
- `src/pe.rs`: the PE headers, the CLR header, and the version resource.
- `tests/`: the synthetic and real-binary tests, and the fixture app.
