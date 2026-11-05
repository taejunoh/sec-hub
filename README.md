# Sec Hub

Sec Hub checks a project folder for known dependency vulnerabilities and opens
the saved results in a desktop app.

## Getting started

The desktop scanner is being prepared for macOS Apple silicon and Windows x64.
This repository state does not include a published download for that scanner.
The older [desktop 0.1.0 release](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.1.0)
is a saved-results viewer; it does not scan projects. See
[Getting started](docs/GETTING-STARTED.md) for the current install, scan, and
results instructions and the release status.

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
