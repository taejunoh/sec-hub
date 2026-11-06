# Getting started with Security Scan Hub Desktop

## 1. Download and open the app

Choose the 0.2.4 prerelease ZIP for your computer. [GitHub release page](https://github.com/taejunoh/security-scan-hub/releases/tag/desktop-v0.2.4)

- **Mac with Apple silicon (M-series).**
  In Finder, double-click the downloaded ZIP. Then double-click **Sec Hub.app**
  (Finder may display it as **Sec Hub**). [Download the signed and notarized Apple silicon ZIP](https://github.com/taejunoh/security-scan-hub/releases/download/desktop-v0.2.4/sec-hub-desktop-0.2.4-darwin-arm64-notarized-prerelease.zip)
- **Intel Mac (x64).** In Finder, double-click the downloaded ZIP to extract
  it, then double-click **Sec Hub.app**. The Intel package bundles OSV Scanner,
  so the first scan runs in the app without Terminal. [Download the signed and
  notarized Intel Mac ZIP](https://github.com/taejunoh/security-scan-hub/releases/download/desktop-v0.2.4/sec-hub-desktop-0.2.4-darwin-x64-notarized-prerelease.zip)
- **Windows x64 (Intel or AMD).**
  In File Explorer, right-click the ZIP, choose **Extract All**, then open
  **Sec Hub.exe** in the extracted **Sec Hub** folder. Keep the extracted files
  together. Windows may show an unknown publisher warning because this build
  has no Sec Hub publisher signature. Keep your system protections enabled; if
  your device blocks the app, check with your administrator. [Download the Windows ZIP](https://github.com/taejunoh/security-scan-hub/releases/download/desktop-v0.2.4/sec-hub-desktop-0.2.4-win32-x64-prerelease.zip)

The app window is titled **Security Scan Hub** on both platforms.

The Intel package requires macOS 13 or later. Release validation targets a
macOS 15 Intel runner; other macOS versions and the other scanner integrations
are not covered by that validation. To use the CLI and local browser instead, see the optional
[Intel Mac Terminal fallback](#intel-mac-scan-from-terminal).

The Windows ZIP requires an x64 PC. If you're downloading from the
release page, look under **Assets** for the ZIP linked above. The
**Source code** archives do not contain the ready-to-run app.

The app includes its runtime and OSV Scanner. You can run your first OSV scan
as soon as you open the app.

To verify a download, use the release's [SHA-256 checksums](https://github.com/taejunoh/security-scan-hub/releases/download/desktop-v0.2.4/sec-hub-desktop-0.2.4-SHA256SUMS.txt).

## 2. Scan a project folder

If the app opens in Korean, use the language menu at the top to switch to
**English**.

1. In **Project security scan** (프로젝트 보안 검사), click **Choose folder**
   (폴더 선택). Select the folder containing the project you want to check, such
   as a JavaScript project with a `package-lock.json` file.
2. Keep **OSV Scanner** selected under **Default scan** (기본 검사), then click
   **Start scan** (검사 시작).
3. When the scan finishes, the saved report opens automatically in the
   **Security Inbox**. To reopen it later, choose **File → Show recent scans**.

## 3. Understand the results

Start with critical and high findings. Open a finding and look under
**What to do next** for **Check first** and **Recommended action**. The app
uses the scanner's saved evidence to show an advisory fix, a tool suggestion,
or the checks to make before deciding what to change.

OSV checks supported dependency files for known vulnerabilities. It needs an
internet connection and may send package names and versions to OSV services.
A completed scan can have findings, and an empty report doesn't prove the
project is safe.

To scan with more tools, configure them and select them before clicking
**Start scan**. AI tools require provider sign-in and consent. A supported Apple
silicon Mac can run all seven integrations after setup. The Cloudflare and Anthropic
workflows are disabled on Windows. [Multi-tool setup guide](../desktop/README.md#run-a-multi-tool-scan)

## Intel Mac: Scan from Terminal

This optional fallback lets Intel Mac users run an OSV scan from Terminal and
review the results in a browser. The Intel desktop package requires macOS 13
or later and targets a macOS 15 Intel runner for release validation. Other
macOS versions and the CLI steps are not covered by that package validation.

1. Install **Node.js 22 or newer** for macOS **x64**, choosing a release
   compatible with your macOS version. [Node.js downloads](https://nodejs.org/en/download)
2. Install **OSV Scanner**. If you already use Homebrew, run
   `brew install osv-scanner`. The verified OSV Scanner 2.7.0 release also
   provides `osv-scanner_darwin_amd64` for Intel Macs. If you use that
   download, name the executable `osv-scanner` and put it on your Terminal's
   PATH. Confirm that `node --version` and `osv-scanner --version` both run.
   [OSV installation guide](https://google.github.io/osv-scanner/installation/) · [OSV Scanner 2.7.0](https://github.com/google/osv-scanner/releases/tag/v2.7.0)
3. Open Terminal and run the commands below. Replace `/path/to/project` with
   the folder you want to scan. A JavaScript project with a
   `package-lock.json` is a good first scan. The output folder must be
   empty or new.

   ```sh
   git clone --branch desktop-v0.2.4 https://github.com/taejunoh/security-scan-hub.git
   cd security-scan-hub
   node bin/sec-hub.mjs scan "/path/to/project" --tools osv --out ./sec-hub-runs/first-scan
   node bin/sec-hub.mjs serve --runs "$PWD/sec-hub-runs"
   ```

4. Open the `127.0.0.1` address printed by Terminal. Select the saved scan
   and a finding to see **What to do next**. Press **Control-C** in Terminal
   when you are done. The scan also saves a standalone HTML report at
   `sec-hub-runs/first-scan/report.html`.
