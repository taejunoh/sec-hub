# Sec Hub desktop

The **Sec Hub desktop 0.2.0 private prerelease** is available from the
[GitHub release page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.0).
Sign in with an account that can access this private repository. Choose
`sec-hub-desktop-0.2.0-darwin-arm64-development.zip` for macOS Apple silicon
or `sec-hub-desktop-0.2.0-win32-x64-prerelease.zip` for Windows x64. The older
[desktop 0.1.0 release](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.1.0)
is a saved-results viewer; it cannot scan a project.

The scanner build bundles a pinned OSV Scanner. Choose a project folder, keep
**OSV Scanner** selected, start the scan, then choose **결과 반영 및 열기**
(*Reflect results and open*) when the scan finishes. OSV may send package names
and versions to Google's advisory and package-metadata services. A completed
scan is not proof that a project is free of vulnerabilities.

The other listed tools are not selectable in this desktop build. Some are AI
tools, but the desktop app does not currently verify their installation or
provider authentication; their login status is shown as unknown. Do not assume
that an AI provider account is connected or that those tools can run here.

## Install and security status

Use the 0.2.0 ZIP for your computer: macOS Apple silicon or Windows x64.
Extract the ZIP before opening the app. The app includes its runtime and OSV
Scanner; no separate Node.js or OSV installation is required.

The macOS app uses an ad-hoc signature, without an Apple developer signing
certificate or notarization. Windows builds do not have a Sec Hub publisher
signature. These are development-build security limitations; this page does
not provide steps to bypass operating-system protections.

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
