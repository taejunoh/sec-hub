# Security Scan Hub

**Run seven security tools in a single scan. Review the results in one place.**
Security Scan Hub combines dependency checks, AI skill scanning, code review,
and URL checks in one report. See the findings and which tools completed,
were skipped, or failed. Results are available as HTML, JSON, and SARIF.

**Desktop quick start.** Download the [desktop prerelease](https://github.com/taejunoh/sec-hub/releases)
and run Google OSV Scanner without a terminal. To run multiple tools,
select them in the app and click **Start scan**. The combined report opens
automatically in the **Security Inbox**. A supported Mac can run all seven
after setup. On Windows, the Cloudflare and Anthropic workflows are disabled.
Follow the [desktop setup guide](desktop/README.md#run-a-multi-tool-scan).

## Seven integrations

| Upstream project | What it checks |
| --- | --- |
| [Google OSV Scanner](https://github.com/google/osv-scanner) | Finds known vulnerabilities in project dependencies. |
| [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) | Scans AI agent skills for suspicious patterns in static mode. |
| [OpenAI Codex Security](https://github.com/openai/codex-security) | Reviews source code for potential vulnerabilities. |
| [Alibaba Open Code Review](https://github.com/alibaba/open-code-review) | Reviews repository code for security and correctness issues. |
| [OpenAI PHP2Shell Checker](https://github.com/openai/php2shell-checker) | Checks the specified URL's response headers for signs of affected PHP versions. |
| [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill) | Runs the upstream audit workflow through the Codex CLI. |
| [Anthropic Defending Code Reference Harness](https://github.com/anthropics/defending-code-reference-harness) | Runs the upstream Claude Code `/vuln-scan` skill in static mode. |

Install the upstream tools and adapt the [seven-tool configuration](examples/seven-tools.config.json)
to your environment. AI workflows require explicit `--ai` opt-in and may send
code or context to the configured provider. The PHP check uses the URL you supply.
SkillSpector requires a target with a top-level `SKILL.md`. With the tools
configured, select all seven in one command:

```sh
node bin/sec-hub.mjs scan /path/to/project \
  --tools osv,skillspector,codex-security,open-code-review,php2shell,cloudflare,anthropic \
  --ai --config /path/to/sec-hub.config.json \
  --url http://127.0.0.1:8080 --timeout 1200 --out ./sec-hub-runs
```

See the [CLI setup and technical reference](docs/REFERENCE.md) for tool
requirements and execution limits. The [verification history](docs/HISTORY.md#031-source-and-seven-tool-validation)
describes how results from the seven integrations were checked and combined.

## Example scan

![Security inbox with findings on the left and the selected advisory on the right](docs/images/security-inbox-wide.png)

The screenshots show the Security Inbox with results from an OSV scan
in the macOS 0.2.0 development build. The demo project's `lodash` 4.17.20
dependency had four findings, two high and two medium. The 0.2.1 prerelease
packages include this inbox.

The inbox puts the highest severity findings first. Search by package, title,
or advisory ID, or filter by severity. Select a finding to read its impact,
affected version, and any fix listed in that advisory. Open **Saved scans and
comparisons** to switch reports, or expand **Original evidence and metadata**
to inspect the source details.

On narrow screens, findings open in a full-width detail view. **Back to
results** restores the search, filters, scroll position, and keyboard focus.

<details>
<summary>See the narrow layout</summary>

![Narrow Security inbox with findings sorted by severity](docs/images/security-inbox-narrow-list.png)

![Narrow finding detail with the advisory and Back to results button](docs/images/security-inbox-narrow-detail.png)

</details>

## Download Sec Hub Desktop 0.2.1

This earlier OSV-only release is listed here for users who need version 0.2.1.
For the current Security Scan Hub desktop build, see [GitHub Releases](https://github.com/taejunoh/sec-hub/releases).

| Your computer | Download |
| --- | --- |
| Mac with Apple silicon (M-series) | [Mac ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-darwin-arm64-notarized-prerelease.zip), signed and notarized |
| Windows x64 (Intel or AMD) | [Windows ZIP](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-win32-x64-prerelease.zip), without a Sec Hub publisher signature. Windows may show an unknown publisher warning. |

This release supports Apple silicon Macs and Windows x64 PCs. Intel Macs
and Windows ARM devices are outside its support range.
[Browse all release assets](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.2.1).
Verify either ZIP with the [SHA-256 checksums](https://github.com/taejunoh/sec-hub/releases/download/desktop-v0.2.1/sec-hub-desktop-0.2.1-SHA256SUMS.txt).

## Run your first scan with 0.2.1

1. **Extract the ZIP.** On Mac, double-click the ZIP and open **Sec Hub.app**.
   On Windows, right-click the ZIP, choose **Extract All**, then open
   **Sec Hub.exe** from the extracted folder. Keep the Windows app files together.
2. In **Project security scan**, click **Choose folder** and select the project
   folder you want to check. For a first scan, choose the root folder of a
   JavaScript project that contains `package-lock.json`. If the app opens in
   Korean, select **English** at the top of the window.
3. Keep **OSV Scanner** selected and click **Start scan**.
4. When the scan finishes, click **Refresh results & open** to read the report
   in the **Security inbox**.
   To open it later, choose **File → Show recent scans**.

A completed scan with no findings means OSV Scanner found no known
vulnerabilities in the dependencies it checked. If the scan fails, check the
error message and try again after resolving it.

[See the full setup and scan guide](docs/GETTING-STARTED.md).

## How the desktop scan works

**Choose a folder → Read the package list → Look up known vulnerabilities →
Save the report**

Electron provides the desktop window. The app starts the
bundled Google OSV Scanner and saves its results for the app to display. You
can run a scan without installing Node.js or creating an OSV account.

OSV Scanner needs internet access and may send package names and versions to
its advisory and package metadata services. The results cover the supported
dependency files that OSV checked.

## For developers

- [Sample report from a multi-tool CLI scan](docs/sample-report.html)
- [Desktop build and packaging notes](desktop/README.md)
- [Release and verification history](docs/HISTORY.md)
