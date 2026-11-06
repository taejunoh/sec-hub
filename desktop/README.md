# Security Scan Hub desktop

If the **Sec Hub Desktop 0.2.1 prerelease** assets are available on the
[GitHub release page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.1),
choose the ZIP for your platform.

- macOS Apple silicon: [Developer ID signed and notarized ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-darwin-arm64-notarized-prerelease.zip)
- Windows x64: [prerelease ZIP; no Sec Hub publisher signature](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-win32-x64-prerelease.zip)
- Checksums for both ZIPs: [SHA256SUMS.txt](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-SHA256SUMS.txt)

The scanner build bundles a pinned OSV Scanner. In **Project security scan**,
choose a folder, keep **OSV Scanner** selected, and start the scan. Choose
**Refresh results & open** when the scan finishes to read the **Security inbox**.
OSV may send package names and versions to Google's advisory and package
metadata services. A completed scan covers the supported dependency files
that OSV checked.

The 0.2.1 download runs OSV. For multi-tool scans, choose the
**Security Scan Hub Desktop 0.2.2** ZIP from [GitHub Releases](https://github.com/taejunoh/sec-hub/releases).
Extract it and open the bundled `Sec Hub.app` or `Sec Hub.exe`. The window
opens under the new **Security Scan Hub** name.

## Run a multi-tool scan

1. Open **Project security scan** and choose the project folder.
2. Open the setup instructions for the tools you want. Install them and sign
   in through their upstream tools where required. Those one-time steps may
   use a terminal.
3. Open **Advanced tool setup** and import a local, trusted JSON file.
   Start from the [seven-tool example](../examples/seven-tools.config.json)
   and replace the example paths with absolute paths on your machine. Keep the
   file outside the project you scan and select it again after restarting the
   app. Use the executable or a native interpreter with its script path. On Windows, use
   an `.exe` rather than a `.cmd` or `.bat` launcher. Select a local
   Node.js 22 or newer executable in the app if prompted.
4. Click **Select all ready tools** or choose individual tools. Provide the
   HTTP(S) URL for PHP2Shell and approve AI use if selected. Click **Start scan**.
   The **Security inbox** opens the combined report when it is ready. Check
   tool coverage for skipped or failed tools.

| Integration | Setup and sign-in |
| --- | --- |
| Google OSV Scanner | Bundled. No account required. Internet access is needed for advisory lookups. |
| NVIDIA SkillSpector | [Install SkillSpector](https://github.com/NVIDIA/SkillSpector). Static mode needs no model account. Choose an individual skill folder with a top-level `SKILL.md`. |
| OpenAI Codex Security | [Install and sign in](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/cli.md#authentication) using the upstream tool, then configure its executable and selected authentication method. |
| Alibaba Open Code Review | [Install Open Code Review](https://github.com/alibaba/open-code-review), then [configure your provider](https://github.com/alibaba/open-code-review/blob/main/pages/src/content/docs/en/cli-reference.md#ocr-auth). ChatGPT sign-in for this tool is a separate flow. |
| OpenAI PHP2Shell Checker | [Get the checker](https://github.com/openai/php2shell-checker) and configure Node.js with the absolute path to `phpcheck.js`. No account required. Use an authorized URL without secrets. |
| Cloudflare Security Audit Skill | [Get the official skill](https://github.com/cloudflare/security-audit-skill) at the example revision. Install and sign in to Codex CLI 0.164.0 on macOS, then configure the checkout and a separate work folder. |
| Anthropic Defending Code | [Get the official harness](https://github.com/anthropics/defending-code-reference-harness) at the example revision and [set up and sign in to Claude Code](https://code.claude.com/docs/en/setup). Configure the checkout and a separate work folder. The app runs the static `/vuln-scan` skill. |

The restricted Cloudflare and Anthropic workflows are available on macOS.
They are disabled on Windows pending validation of their restricted
execution environments there. The other integrations can be configured
individually. Authentication is handled by each provider. AI tools may send project
data to the configured provider and consume usage or incur charges.

## Install and security status

Use the 0.2.1 ZIP for your computer: macOS Apple silicon or Windows x64.
Extract the ZIP before opening the app. The app includes its runtime and OSV
Scanner; no separate Node.js or OSV installation is required.

The macOS ZIP is Developer ID signed, notarized, and stapled; its packaged app
passed `spctl` and stapler verification. Windows builds have no Sec Hub
publisher signature. Do not disable operating-system protections to open an
app you do not trust.

## Build and package checks

For maintainers, build on the matching OS and architecture with
`node desktop/build.mjs --target <darwin-arm64|win32-x64> --out <absolute-empty-output> --cache <absolute-cache>`.
Windows x64 packaging requires an x64 Visual Studio Developer Command Prompt,
MSVC, and the Windows SDK. `node desktop/smoke.mjs --executable <absolute-packaged-app> --out <absolute-empty-evidence-directory>`
checks the packaged scan and shutdown; its fixture scan needs network access to
OSV.


[The OSV lock](app/osv-lock.json) pins the upstream version, executable sizes
and SHA-256 checksums, and Apache-2.0 license. Packaging verifies the files
before staging and checks the executable again after signing. The manifest
records the source and executable digest. The unpacked scanner adds about
55 MB on macOS or 59 MB on Windows. To update the pin, cross-check the
official checksum file and release asset digest, update the desktop lock and
core adapter together, and run the packaged smoke on both platforms.

**File → Show recent scans** opens reports saved by this app. **Open saved
view in browser** opens the example or an explicitly opened saved-results
folder. Recent scans remain available from the app window.
