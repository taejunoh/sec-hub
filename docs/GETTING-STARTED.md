# Getting started with Sec Hub Desktop

## 1. Download and open the app

[Sec Hub Desktop 0.2.1](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.1)
is a private prerelease. Sign in to GitHub with an account that has access to
the Sec Hub repository. If the link shows a 404, check that you're signed in
with the right account or ask the repository owner for access.

- **Mac with Apple silicon (M-series):** [Download the signed and notarized Mac ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-darwin-arm64-notarized-prerelease.zip).
  In Finder, double-click the downloaded ZIP. Then double-click **Sec Hub.app**
  (Finder may display it as **Sec Hub**).
- **Windows x64 (Intel or AMD):** [Download the Windows ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-win32-x64-prerelease.zip).
  In File Explorer, right-click the ZIP, choose **Extract All**, then open
  **Sec Hub.exe** in the extracted **Sec Hub** folder. Keep the extracted files
  together. Windows may show an unknown publisher warning because this build
  has no Sec Hub publisher signature. Keep your system protections enabled; if
  your device blocks the app, check with your administrator.

Intel Macs and Windows ARM devices are unsupported. If you're downloading from
the release page, look under **Assets** for the ZIP linked above. The
**Source code** archives do not contain the ready-to-run app.

The app includes OSV Scanner. You don't need to install Node.js, install OSV
Scanner separately, or create an OSV account.

To verify either download, use the release's [SHA-256 checksums](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-SHA256SUMS.txt).

## 2. Scan a project folder

If the app opens in Korean, use the language menu at the top to switch to
**English**.

1. In **Project security scan** (프로젝트 보안 검사), click **Choose folder**
   (폴더 선택). Select the folder containing the project you want to check, such
   as a JavaScript project with a `package-lock.json` file.
2. Keep **OSV Scanner** selected under **Default scan** (기본 검사), then click
   **Start scan** (검사 시작).
3. When the scan finishes, click **Refresh results & open** (결과 반영 및 열기)
   to see the saved report in the Security inbox. To reopen it later, choose
   **File → Show recent scans**.

## 3. Understand the results

OSV checks supported dependency files for known vulnerabilities. It needs an
internet connection and may send package names and versions to OSV services.
A completed scan can have findings, and an empty report doesn't prove the
project is safe.

OSV is the only scanner this desktop release can run. Other scanners,
including AI tools, may appear in the setup section. The app cannot run them
or confirm whether they are installed or signed in to a provider.

The [older desktop 0.1.0 release](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.1.0)
can open saved reports but cannot scan projects.
