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
    /// Native code, or a file dotnot finds no .NET signal in.
    NotDotnet,
}
