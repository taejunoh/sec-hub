# Getting started

## Download the prerelease

Open the [Sec Hub Desktop 0.2.0 private prerelease page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.0)
and sign in to GitHub with an account that has access to this private
repository. Download the matching package:

- **macOS Apple silicon, recommended:** [Developer ID signed and notarized ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-darwin-arm64-notarized-prerelease.zip)
- **macOS development variant:** [ad-hoc signed ZIP, not notarized](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-darwin-arm64-development.zip)
- **Windows x64:** [prerelease ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-win32-x64-prerelease.zip) (no Sec Hub publisher signature)

The [macOS notarized package checksums](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.0/sec-hub-desktop-0.2.0-macos-notarized-SHA256SUMS.txt)
are on the same release page.

These packages support macOS on Apple silicon and Windows x64. Intel Macs and
Windows ARM are not supported. Extract the ZIP before opening the app. On
Windows, keep the extracted files together.

The app includes its runtime and OSV Scanner. You do not need to install
Node.js, OSV Scanner, or create an OSV account separately.

## Install and run a scan

1. Open `Sec Hub.app` on macOS or `Sec Hub.exe` on Windows.
2. In **프로젝트 보안 검사** (*Project security scan*), choose **폴더 선택**
   (*Choose folder*) and select the project folder you want to check.
3. Confirm OSV Scanner is available and selected under **기본 검사** (*Default
   scan*), then choose **검사 시작** (*Start scan*).
4. When the scan finishes, choose **결과 반영 및 열기** (*Reflect results and
   open*) to add the report to the results list. Choose **Show recent scans**
   from the File menu to reopen reports saved by this app later.

OSV checks supported dependency files for known vulnerabilities. It needs
network access to query OSV's advisory and package-metadata services; package
names and versions may be sent. A scan result describes the checks that ran,
not a guarantee that the project is safe or vulnerability-free. A scan with
findings is still a completed scan.

## Optional tools and sign-in

The app may list other scanners, including AI tools, but they are currently
unavailable to run from this desktop build. Sec Hub does not confirm whether
those tools are installed or whether a provider account is signed in; AI
authentication is shown as **unknown**. The app's per-run confirmation for
code transfer and possible provider charges does not mean that an account has
been authenticated or that the provider call will succeed.

## Signing and opening

The recommended macOS ZIP is signed with an Apple Developer ID, notarized, and
has its notarization ticket stapled. The packaged app passed independent
Gatekeeper policy (`spctl`) and stapler checks. The separate macOS development
ZIP remains ad-hoc signed, with no Apple developer certificate or
notarization. Windows packages have no Sec Hub publisher signature, so Windows
may show an unknown-publisher warning. Do not disable operating-system
protections to open an app you do not trust.

The older [desktop 0.1.0 release](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.1.0)
can open saved results and its example, but it cannot perform scans.
