//! The answer: what kind of .NET executable a file is, if any.

/// What kind of .NET executable a file is, if any.
///
/// mirrord's `exec` picks how to hold a service's root process from this. A .NET (Core / 5+)
/// program pauses at the runtime's own startup, through `DOTNET_DiagnosticPorts`. Anything
/// else is held at process creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DotnetKind {
    /// A .NET (Core / 5+) app's own native launcher, like `Shop.Orders.Api.exe` next to
    /// `Shop.Orders.Api.dll`.
    ///
    /// Found by the bundle marker every apphost carries, on every platform.
    Apphost {
        /// The app is bundled into the apphost (`PublishSingleFile`): the bundle header
        /// offset in front of the marker is nonzero.
        single_file: bool,
    },
    /// `dotnet` itself: the host that starts `dotnet app.dll` and `dotnet run`.
    ///
    /// Found by its version resource in a PE, and by its built-in usage line in ELF and
    /// Mach-O, which have no version resource.
    Muxer,
    /// A PE image with a CLR header: managed code that the CLR loads.
    ///
    /// An `.exe` with one is a .NET Framework program, held at process creation. An IL-only
    /// `.dll` of a .NET (Core / 5+) app has one too, but it never starts on its own: its
    /// apphost or the muxer starts it, and those are what mirrord classifies.
    FrameworkAssembly,
    /// Native code, or a file dotnot finds no .NET signal in.
    NotDotnet,
}
