//! The decision against real binaries from this machine, found or built at test time.
//!
//! The .NET cases need the `dotnet` SDK on PATH, and skip without it, saying so; set
//! `DOTNOT_REQUIRE_DOTNET=1` to fail instead. A fixture that fails to build fails its tests.
//!
//! NOTE: this file must never hold the bundle signature or the muxer's usage line itself:
//! one test classifies this very binary, which links dotnot, and expects `NotDotnet`.

mod common;

use common::Garbage;
use dotnot::{DotnetKind, Error, classify, classify_bytes};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

/// A binary, and what it must classify as.
struct Case {
    name: &'static str,
    path: PathBuf,
    expected: DotnetKind,
}

/// Classifies every case, from the path and from its bytes, and reports all mismatches at
/// once.
fn check(cases: &[Case]) {
    let mut wrong = Vec::new();
    for case in cases {
        let from_path = classify(&case.path);
        let bytes = fs::read(&case.path).unwrap_or_else(|error| {
            panic!(
                "{}: {} is unreadable: {error}",
                case.name,
                case.path.display()
            )
        });
        let from_bytes = classify_bytes(&bytes);
        let from_path_ok = matches!(&from_path, Ok(kind) if *kind == case.expected);
        let from_bytes_ok = matches!(&from_bytes, Ok(kind) if *kind == case.expected);
        if !from_path_ok || !from_bytes_ok {
            wrong.push(format!(
                "{}: expected {:?}, the path gave {from_path:?} and the bytes {from_bytes:?} ({})",
                case.name,
                case.expected,
                case.path.display()
            ));
        }
    }
    assert!(wrong.is_empty(), "misclassified:\n{}", wrong.join("\n"));
}

/// The `dotnet` on PATH, as `where dotnet` or `which dotnet` would find it.
fn dotnet_on_path() -> Option<PathBuf> {
    let name = format!("dotnet{}", env::consts::EXE_SUFFIX);
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(&name))
        .find(|path| path.is_file())
}

/// The muxer and the fixture app's outputs, built once per run of this file.
struct Dotnet {
    muxer: PathBuf,
    apphost: PathBuf,
    il: PathBuf,
    single_file: PathBuf,
}

/// The muxer and the built fixture, or `None` when there's no SDK to build with.
fn dotnet() -> Option<&'static Dotnet> {
    static DOTNET: OnceLock<Option<Dotnet>> = OnceLock::new();
    DOTNET
        .get_or_init(|| {
            let Some(muxer) = dotnet_on_path() else {
                assert!(
                    env::var_os("DOTNOT_REQUIRE_DOTNET").is_none(),
                    "DOTNOT_REQUIRE_DOTNET is set, but there's no dotnet on PATH"
                );
                eprintln!("skipped: no dotnet on PATH to build the fixture with");
                return None;
            };
            Some(build_fixture(muxer))
        })
        .as_ref()
}

/// Builds `tests/fixtures/hello` twice, offline: a plain build, and a single-file publish.
fn build_fixture(muxer: PathBuf) -> Dotnet {
    let root = common::scratch_dir("hello");
    let project = root.join("project");
    let feed = root.join("empty-feed");
    fs::create_dir_all(&project).expect("the scratch dir is writable");
    fs::create_dir_all(&feed).expect("the scratch dir is writable");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hello");
    for file in [
        "Hello.csproj",
        "Program.cs",
        "Directory.Build.props",
        "Directory.Build.targets",
    ] {
        fs::copy(fixture.join(file), project.join(file)).expect("the fixture files exist");
    }

    let build = root.join("build");
    let single_file = root.join("single-file");
    run_dotnet(&muxer, &project, &feed, &["build", "-o"], &build, &[]);
    run_dotnet(
        &muxer,
        &project,
        &feed,
        &["publish", "-o"],
        &single_file,
        &[
            "--use-current-runtime",
            "--self-contained",
            "false",
            "-p:PublishSingleFile=true",
        ],
    );

    let apphost = format!("Hello{}", env::consts::EXE_SUFFIX);
    Dotnet {
        muxer,
        apphost: build.join(&apphost),
        il: build.join("Hello.dll"),
        single_file: single_file.join(&apphost),
    }
}

/// Runs one `dotnet` command on the fixture, offline and without build servers, so nothing
/// downloads and no compiler server outlives the test.
fn run_dotnet(
    muxer: &Path,
    project: &Path,
    feed: &Path,
    verb_and_output: &[&str],
    output: &Path,
    extra: &[&str],
) {
    let result = Command::new(muxer)
        .args(verb_and_output)
        .arg(output)
        .arg(project.join("Hello.csproj"))
        .args([
            "-c",
            "Release",
            "--nologo",
            "--disable-build-servers",
            "-p:UseSharedCompilation=false",
            "--source",
        ])
        .arg(feed)
        .args(extra)
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1")
        .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
        .env("MSBUILDDISABLENODEREUSE", "1")
        .output()
        .expect("dotnet on PATH runs");
    assert!(
        result.status.success(),
        "dotnet {verb_and_output:?} failed with {}:\n{}\n{}",
        result.status,
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

/// On Windows the muxer is told by its version resource; on Linux and macOS, by its usage
/// line. Both run here, on whichever platform the tests do.
#[test]
fn dotnet_binaries_from_this_machine_classify_as_their_kind() {
    let Some(dotnet) = dotnet() else { return };
    check(&[
        Case {
            name: "the muxer on PATH",
            path: dotnet.muxer.clone(),
            expected: DotnetKind::Muxer,
        },
        Case {
            name: "the fixture's apphost",
            path: dotnet.apphost.clone(),
            expected: DotnetKind::Apphost { single_file: false },
        },
        Case {
            name: "the fixture's single-file publish",
            path: dotnet.single_file.clone(),
            expected: DotnetKind::Apphost { single_file: true },
        },
        // An IL .dll is a PE with a CLR header on every platform.
        Case {
            name: "the fixture's IL .dll",
            path: dotnet.il.clone(),
            expected: DotnetKind::FrameworkAssembly,
        },
    ]);
}

#[cfg(windows)]
#[test]
fn windows_system_binaries_classify_as_their_kind() {
    let windows = PathBuf::from(env::var_os("SystemRoot").expect("Windows sets SystemRoot"));
    let framework = windows.join(r"Microsoft.NET\Framework64\v4.0.30319");
    check(&[
        Case {
            name: "RegAsm, a .NET Framework program",
            path: framework.join("RegAsm.exe"),
            expected: DotnetKind::FrameworkAssembly,
        },
        Case {
            name: "InstallUtil, a .NET Framework program",
            path: framework.join("InstallUtil.exe"),
            expected: DotnetKind::FrameworkAssembly,
        },
        Case {
            name: "notepad",
            path: windows.join(r"System32\notepad.exe"),
            expected: DotnetKind::NotDotnet,
        },
        // The odd one out: it lives with the .NET Framework, but it's a native launcher today.
        Case {
            name: "csc, the .NET Framework compiler",
            path: framework.join("csc.exe"),
            expected: DotnetKind::NotDotnet,
        },
    ]);
}

/// Linking dotnot must not make a binary look like .NET: mirrord itself links it.
#[test]
fn a_binary_that_links_dotnot_is_not_dotnet() {
    check(&[Case {
        name: "this test binary",
        path: env::current_exe().expect("the test binary has a path"),
        expected: DotnetKind::NotDotnet,
    }]);
}

/// Every cut of a real header region gives a whole answer or a typed error, never a panic.
#[test]
fn truncated_real_binaries_decide_or_report_malformed_headers() {
    let Some(dotnet) = dotnet() else { return };
    for path in [&dotnet.muxer, &dotnet.apphost, &dotnet.il] {
        let bytes = fs::read(path).expect("the binary was just found or built");
        let cuts = (0..bytes.len().min(8192)).chain((8192..bytes.len()).step_by(4093));
        for len in cuts {
            match classify_bytes(&bytes[..len]) {
                Ok(_) | Err(Error::MalformedPe(_)) => {}
                Err(other) => panic!("{} cut to {len} bytes gave {other:?}", path.display()),
            }
        }
    }
}

/// Noise written into real binaries, resources included, can make any answer, but never a
/// panic.
#[test]
fn real_binaries_full_of_noise_never_panic() {
    let Some(dotnet) = dotnet() else { return };
    let mut garbage = Garbage::new(0xd07_0070);
    for path in [&dotnet.muxer, &dotnet.apphost, &dotnet.il] {
        let pristine = fs::read(path).expect("the binary was just found or built");
        for _ in 0..200 {
            let mut bytes = pristine.clone();
            for _ in 0..1 + garbage.next() % 64 {
                let at = (garbage.next() % bytes.len() as u64) as usize;
                bytes[at] = garbage.next() as u8;
            }
            let _ = classify_bytes(&bytes);
        }
    }
}
