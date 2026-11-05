# Sec Hub

Sec Hub checks a project folder for known dependency vulnerabilities and opens
the saved results in a desktop app.

## Getting started

Download the **desktop 0.2.0 private prerelease** from the
[GitHub release page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.0).
Sign in to GitHub with an account that has access to this private repository.
Choose `sec-hub-desktop-0.2.0-darwin-arm64-development.zip` for macOS Apple
silicon or `sec-hub-desktop-0.2.0-win32-x64-prerelease.zip` for Windows x64.
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
