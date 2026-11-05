# Getting started

## Download the prerelease

Open the [Sec Hub Desktop 0.2.0 private prerelease page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.0)
and sign in to GitHub with an account that has access to this private
repository. Download the matching package:

- **macOS Apple silicon:** `sec-hub-desktop-0.2.0-darwin-arm64-development.zip`
- **Windows x64:** `sec-hub-desktop-0.2.0-win32-x64-prerelease.zip`

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

## Opening warnings

The macOS development app is ad-hoc signed. It has no Apple developer signing
certificate and is not notarized. Windows builds have no Sec Hub publisher
signature. Your operating system may show a warning. These packages do not
provide the publisher verification associated with signed, notarized releases.
Do not disable operating-system protections to open an app you do not trust.

The older [desktop 0.1.0 release](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.1.0)
can open saved results and its example, but it cannot perform scans.
