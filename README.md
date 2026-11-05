# Sec Hub

Sec Hub is a desktop app that checks a project folder for known vulnerabilities
in its software dependencies and lets you review the results.

## Download Sec Hub Desktop 0.2.0

This is a **private prerelease**. Sign in to GitHub with an account that has
access to this repository, then download the ZIP for your computer:

- **Mac with Apple silicon (M-series):** [Download the signed and notarized Mac ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-darwin-arm64-notarized-prerelease.zip)
- **Windows x64 (Intel or AMD):** [Download the Windows ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-win32-x64-prerelease.zip). Windows may show an unknown publisher warning because this build has no Sec Hub publisher signature.

Intel Macs and Windows ARM devices are unsupported. If you need to find the
files manually, open the [release page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.0)
and look under **Assets**.

## Run your first scan

1. **Extract the ZIP.** On Mac, double-click the ZIP and open **Sec Hub.app**. On
   Windows, right-click the ZIP, choose **Extract All**, then open **Sec Hub.exe**
   from the extracted folder. Keep the Windows app files together.
2. In **Project security scan**, click **Choose folder** and select the project
   folder you want to check. If the app opens in Korean, select **English** at
   the top of the window.
3. Leave **OSV Scanner** selected and click **Start scan**.
4. When the scan finishes, click **Refresh results & open** to read the report.

[See the full setup and scan guide](docs/GETTING-STARTED.md), including how to
reopen saved reports.

OSV Scanner comes with the app. You don't need to install Node.js or create an
OSV account. The scanner needs an internet connection and may send package
names and versions to look up known vulnerabilities. OSV is the only
scanner this desktop release can run. Other tools, including AI scanners, may
be listed for setup guidance. An empty report does not mean the project is safe.

## Other project material

- [CLI 0.3.2 package](releases/sec-hub-local-0.3.2.tgz) and its
  [technical reference](docs/REFERENCE.md)
- [Sample report](docs/sample-report.html)
- [Release and verification history](docs/HISTORY.md)
- [Seven-tool validation record](verification/seven-tools-validation-2026-10-29/REPORT.md)
