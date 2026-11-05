# Sec Hub

Sec Hub is a desktop app that checks a software project for known
vulnerabilities in the packages it depends on. Choose a project folder, run a
scan, and open a report that shows which packages were flagged and why.

## Why it exists

Security scanners often have their own setup, commands, and output formats.
Sec Hub started as a command-line tool that brings those results together in a
consistent report and shows which checks ran. The desktop app makes the most
common first step, checking a project's dependencies, available without a
terminal.

## Download Sec Hub Desktop 0.2.0

This is a **private prerelease**. Sign in to GitHub with an account that has
access to the Sec Hub repository.

| Your computer | Download |
| --- | --- |
| Mac with Apple silicon (M-series) | [Mac ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-darwin-arm64-notarized-prerelease.zip), signed and notarized |
| Windows x64 (Intel or AMD) | [Windows ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-win32-x64-prerelease.zip), without a Sec Hub publisher signature. Windows may show an unknown publisher warning. |

This release supports Apple silicon Macs and Windows x64 PCs. Intel Macs
and Windows ARM devices are outside its support range.
[Browse all release assets](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.0).

## Run your first scan

1. **Extract the ZIP.** On Mac, double-click the ZIP and open **Sec Hub.app**.
   On Windows, right-click the ZIP, choose **Extract All**, then open
   **Sec Hub.exe** from the extracted folder. Keep the Windows app files together.
2. In **Project security scan**, click **Choose folder** and select the project
   folder you want to check. If the app opens in Korean, select **English** at
   the top of the window.
3. Keep **OSV Scanner** selected and click **Start scan**.
4. When the scan finishes, click **Refresh results & open** to read the report.
   To open it later, choose **File → Show recent scans**.

[See the full setup and scan guide](docs/GETTING-STARTED.md).

## How it works

The desktop app was built with Electron and uses Sec Hub's Node.js scanning
and reporting code. It bundles Google's OSV Scanner, so you can run a scan
without installing Node.js or creating an OSV account.

OSV Scanner reads supported dependency files, such as `package-lock.json`,
and looks up known vulnerabilities. It needs an internet connection and may
send package names and versions to OSV's advisory and package metadata
services. If a completed scan reports no findings, it found no known
vulnerabilities in the dependencies it checked. It cannot establish that the
whole project is safe.

OSV Scanner is the only scanner this desktop release runs. Other tools,
including AI scanners, may appear in the app for setup guidance.

## For developers

- [CLI 0.3.2 package](releases/sec-hub-local-0.3.2.tgz) and its
  [technical reference](docs/REFERENCE.md)
- [Sample report from a multi-tool CLI scan](docs/sample-report.html)
- [Desktop build and packaging notes](desktop/README.md)
- [Release and verification history](docs/HISTORY.md)
- [Seven-tool validation record](verification/seven-tools-validation-2026-10-29/REPORT.md)
