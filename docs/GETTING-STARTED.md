# Getting started with Security Scan Hub Desktop

## 1. Download and open the app

Choose the 0.2.3 prerelease ZIP for your computer. [GitHub release page](https://github.com/taejunoh/security-scan-hub/releases/tag/desktop-v0.2.3)

- **Mac with Apple silicon (M-series).**
  In Finder, double-click the downloaded ZIP. Then double-click **Sec Hub.app**
  (Finder may display it as **Sec Hub**). [Download the signed and notarized Mac ZIP](https://github.com/taejunoh/security-scan-hub/releases/download/desktop-v0.2.3/sec-hub-desktop-0.2.3-darwin-arm64-notarized-prerelease.zip)
- **Windows x64 (Intel or AMD).**
  In File Explorer, right-click the ZIP, choose **Extract All**, then open
  **Sec Hub.exe** in the extracted **Sec Hub** folder. Keep the extracted files
  together. Windows may show an unknown publisher warning because this build
  has no Sec Hub publisher signature. Keep your system protections enabled; if
  your device blocks the app, check with your administrator. [Download the Windows ZIP](https://github.com/taejunoh/security-scan-hub/releases/download/desktop-v0.2.3/sec-hub-desktop-0.2.3-win32-x64-prerelease.zip)

The app window is titled **Security Scan Hub** on both platforms.

Intel Macs and Windows ARM devices are unsupported. If you're downloading from
the release page, look under **Assets** for the ZIP linked above. The
**Source code** archives do not contain the ready-to-run app.

The app includes its runtime and OSV Scanner. You can run your first OSV scan
as soon as you open the app.

To verify either download, use the release's [SHA-256 checksums](https://github.com/taejunoh/security-scan-hub/releases/download/desktop-v0.2.3/sec-hub-desktop-0.2.3-SHA256SUMS.txt).

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
**Start scan**. AI tools require provider sign-in and consent. A supported Mac
can run all seven integrations after setup. The Cloudflare and Anthropic
workflows are disabled on Windows. [Multi-tool setup guide](../desktop/README.md#run-a-multi-tool-scan)
