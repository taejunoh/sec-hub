# Sec Hub

Run local scans on a project and review results in your browser.

[0.3.0 package](releases/sec-hub-local-0.3.0.tgz) · [Hosted CI passed](verification/ci-after-budget-2026-10-28/REPORT.md)

## Choose a path

| If you want to… | Start here |
| --- | --- |
| See what a report looks like | [Download sample report](https://github.com/taejunoh/sec-hub/raw/refs/heads/main/docs/sample-report.html) |
| Scan a project you own | [First scan](#scan-your-project-on-macos-or-linux) on macOS or Linux. |

### View a saved sample

1. Use the **Download sample report** link above. GitHub access to this private repository may require sign-in.

2. If the browser displays the report, use Save As to save it as `sample-report.html`.

3. Open the saved file in your browser.

This self-contained report is from a controlled test project, not your project or
a security verdict. It opens in a browser; no Node.js, scanner, or AI login is
needed.

### Scan your project on macOS or Linux

| Tool | How to get it |
| --- | --- |
| Node.js | Install [Node.js 24 LTS](https://nodejs.org/en/download); choose 24 on the download page. Requires Node 22+; tested on 22/24. |
| OSV Scanner | Install separately using the [official instructions](https://google.github.io/osv-scanner/installation/). If Homebrew is already installed, run `brew install osv-scanner`. |

No `npm install` is needed.

#### 1. Prepare

Download the Sec Hub repository using GitHub **Code → Download ZIP**, extract it, and open a terminal in the extracted folder containing `bin/` and `package.json`.

```sh
node --version
node bin/sec-hub.mjs doctor .
```

Check that `doctor` reports `osv` available. It can exit 0 even if a scanner is missing.

#### 2. Scan

Replace the example with the absolute path to a project folder you own. OSV Scanner reads supported dependency files, such as `package-lock.json`, and may use the network to look up vulnerabilities.

```sh
node bin/sec-hub.mjs scan "/absolute/path/to/your/project" --tools osv
```

#### 3. Review

From the Sec Hub repository folder, serve the saved results:

```sh
node bin/sec-hub.mjs serve --runs "$PWD/.sec-hub/runs"
```

Open the `127.0.0.1` URL printed in the terminal. Keep the terminal open while viewing results; press **Ctrl+C** there to stop the server. The new scan is saved under `.sec-hub/runs/<generated-run-id>` in the Sec Hub folder. The server only displays saved results; it does not start another scan.

A scan that exits **1** completed with findings; it did not fail. Exit **0** means it completed with no findings. Exit **2** means an error or incomplete scan. Review the result and tool coverage; a scan cannot prove that a project is vulnerability-free.

| Problem | Check |
| --- | --- |
| `node` is not found | Install Node.js 24 LTS and open a new terminal. |
| `doctor` says OSV is unavailable | Install OSV Scanner separately, then run `doctor` again. |
| The scan exits 1 | It completed with findings. Open them in the results page. |
| Report writing is unsupported on Windows | Run scans on macOS or Linux. Windows can open the saved HTML sample. |

## More detail

- [Technical reference](docs/REFERENCE.md): advanced commands, saved reports, web execution, integrations, and security limits.

- [Release and verification history](docs/HISTORY.md): earlier versions and their evidence.

- [Latest CI report](verification/ci-after-budget-2026-10-28/REPORT.md): per-platform results for the latest successful run.

This quick start uses OSV only. Other tools may need credentials or upload code.
Anthropic remains deferred; read the technical reference before enabling them.
