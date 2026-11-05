# Sec Hub

Sec Hub checks a project folder for known dependency vulnerabilities and opens
the saved results in a desktop app.

## Getting started

Download the **desktop 0.2.0 private prerelease** from the
[GitHub release page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.0).
Sign in to GitHub with an account that has access to this private repository.

- macOS Apple silicon: [Developer ID signed and notarized ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-darwin-arm64-notarized-prerelease.zip)
- macOS development variant: [ad-hoc signed ZIP, not notarized](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-darwin-arm64-development.zip)
- Windows x64: [prerelease ZIP; no Sec Hub publisher signature](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-win32-x64-prerelease.zip)

The older [desktop 0.1.0 release](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.1.0)
is a saved-results viewer; it does not scan projects. See
[Getting started](docs/GETTING-STARTED.md) for install and scan instructions.

The desktop app includes OSV Scanner, so no separate Node.js or scanner install
is needed. OSV may send package names and versions over the network to look up
known vulnerabilities. Other listed tools are not currently available to run
from this desktop build. Their installation or provider sign-in status cannot
be confirmed by Sec Hub.

## Other project material

- [CLI 0.3.2 package](releases/sec-hub-local-0.3.2.tgz) and its
  [technical reference](docs/REFERENCE.md)
- [Sample report](docs/sample-report.html)
- [Release and verification history](docs/HISTORY.md)
- [Seven-tool validation record](verification/seven-tools-validation-2026-10-29/REPORT.md)
