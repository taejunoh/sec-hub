# Sec Hub desktop

The **Sec Hub desktop 0.2.1 private prerelease** is available from the
[GitHub release page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.1).
Sign in with an account that can access this private repository. Download:

- macOS Apple silicon: [Developer ID signed and notarized ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-darwin-arm64-notarized-prerelease.zip)
- Windows x64: [prerelease ZIP; no Sec Hub publisher signature](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-win32-x64-prerelease.zip)
- Checksums for both ZIPs: [SHA256SUMS.txt](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-SHA256SUMS.txt)

The older
[desktop 0.1.0 release](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.1.0)
is a saved-results viewer; it cannot scan a project.

The scanner build bundles a pinned OSV Scanner. In **Project security scan**,
choose a folder, keep **OSV Scanner** selected, and start the scan. Choose
**Refresh results & open** when the scan finishes to read the **Security inbox**.
OSV may send package names and versions to Google's advisory and package
metadata services. A completed scan covers the supported dependency files
that OSV checked.

The other listed tools are not selectable in this desktop build. Some are AI
tools, but the desktop app does not currently verify their installation or
provider authentication; their login status is shown as unknown. Do not assume
that an AI provider account is connected or that those tools can run here.

## Install and security status

Use the 0.2.1 ZIP for your computer: macOS Apple silicon or Windows x64.
Extract the ZIP before opening the app. The app includes its runtime and OSV
Scanner; no separate Node.js or OSV installation is required.

The macOS ZIP is Developer ID signed, notarized, and stapled; its packaged app
passed `spctl` and stapler verification. Windows builds have no Sec Hub
publisher signature. Do not disable operating-system protections to open an
app you do not trust.

## Build and package checks

For maintainers, build on the matching OS and architecture with
`node desktop/build.mjs --target <darwin-arm64|win32-x64> --out <absolute-empty-output> --cache <absolute-cache>`.
Windows x64 packaging requires an x64 Visual Studio Developer Command Prompt,
MSVC, and the Windows SDK. `node desktop/smoke.mjs --executable <absolute-packaged-app> --out <absolute-empty-evidence-directory>`
checks the packaged scan and shutdown; its fixture scan needs network access to
OSV.


[The OSV lock](app/osv-lock.json) pins the upstream version, executable sizes
and SHA-256 checksums, and Apache-2.0 license. Packaging verifies the files
before staging and checks the executable again after signing. The manifest
records the source and executable digest. The unpacked scanner adds about
55 MB on macOS or 59 MB on Windows. To update the pin, cross-check the
official checksum file and release asset digest, update the desktop lock and
core adapter together, and run the packaged smoke on both platforms.

**File → Show recent scans** opens reports saved by this app. **Open saved
view in browser** opens the example or an explicitly opened saved-results
folder. Recent scans remain available from the app window.
