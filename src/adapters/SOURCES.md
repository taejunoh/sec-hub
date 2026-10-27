# Verified native contracts

These adapters were checked against installed official CLIs and upstream source on 2026-10-27. Native output is untrusted input. JSON files are limited to 20 MiB, malformed or unsupported documents fail parsing, and unknown severity remains unknown. The examples in `test/fixtures/adapters/` are synthetic contract fixtures, not evidence of authenticated scans.

| Adapter | Verified version | Official contract |
| --- | --- | --- |
| `osv` | OSV Scanner v2.7.0 | [source command](https://github.com/google/osv-scanner/blob/v2.7.0/cmd/osv-scanner/scan/source/command.go), [JSON models](https://github.com/google/osv-scanner/blob/v2.7.0/pkg/models/results.go), [call analysis controls](https://github.com/google/osv-scanner/blob/v2.7.0/cmd/osv-scanner/internal/helper/callanalysis_parser.go) |
| `skillspector` | v2.12.0, commit `a5425e594d59a14c3d3eaa39e26847613ba08696` | [CLI](https://github.com/NVIDIA/skillspector/blob/a5425e594d59a14c3d3eaa39e26847613ba08696/src/skillspector/cli.py), [JSON rendering](https://github.com/NVIDIA/skillspector/blob/a5425e594d59a14c3d3eaa39e26847613ba08696/src/skillspector/nodes/report.py), [finding model](https://github.com/NVIDIA/skillspector/blob/a5425e594d59a14c3d3eaa39e26847613ba08696/src/skillspector/models.py) |
| `codex-security` | npm `@openai/codex-security@0.7.0` | [CLI guide](https://github.com/openai/codex-security/blob/main/sdk/typescript/docs/cli.md), [exported findings schema](https://github.com/openai/codex-security/blob/main/plugins/codex-security/schemas/findings.schema.json); also checked packaged CLI help |
| `open-code-review` | npm `@alibaba-group/open-code-review@1.13.3` | [scan implementation](https://github.com/alibaba/open-code-review/blob/main/cmd/opencodereview/scan_cmd.go), [scan flags](https://github.com/alibaba/open-code-review/blob/main/cmd/opencodereview/shared_flags.go), [JSON output](https://github.com/alibaba/open-code-review/blob/main/cmd/opencodereview/output.go), [comment model](https://github.com/alibaba/open-code-review/blob/main/internal/model/review.go); also checked installed CLI help |
| `php2shell` | commit `ffcd3fc82e5b404f2a04a95b2805ca7639d530fa` | [official checker](https://github.com/openai/php2shell-checker/blob/ffcd3fc82e5b404f2a04a95b2805ca7639d530fa/skills/phpcheck-url/scripts/phpcheck.js) |

## Installation and native invocation

Installation is always an operator action. Install scanners outside the scanned repository. Pin the versions above when reproducing this verification; future upstream output changes can require parser updates.

```sh
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0
uv tool install git+https://github.com/NVIDIA/skillspector.git@a5425e594d59a14c3d3eaa39e26847613ba08696
npm install -g @openai/codex-security@0.7.0
npm install -g @alibaba-group/open-code-review@1.13.3
git clone https://github.com/openai/php2shell-checker.git /absolute/tools/php2shell-checker
git -C /absolute/tools/php2shell-checker checkout ffcd3fc82e5b404f2a04a95b2805ca7639d530fa
```

The native invocations appended after configured executable/argv prefixes are:

```sh
osv-scanner scan source -r --no-resolve --no-call-analysis=go --no-call-analysis=rust --format json --output-file /absolute/artifacts/native.json /absolute/repo
skillspector scan /absolute/skill --no-llm --format json --output /absolute/artifacts/native.json
cs scan /absolute/repo --output-dir /private/outside-all-worktrees/results --headless --json
cs export /private/outside-all-worktrees/results --export-format json --output /absolute/artifacts/findings.json
ocr scan --repo /absolute/repo --format json --output /absolute/artifacts/native.json
node /absolute/tools/php2shell-checker/phpcheck.js http://127.0.0.1:8080/ --json
```

`check()` only runs the native `--version` with a 10 second timeout and a 64 KiB output cap through the same bounded process runner as scans. Timeout, cancellation and excess output trigger SIGTERM, followed by SIGKILL after 300 ms; Unix process groups include descendants. A final deadline bounds waiting for inherited pipes. `ctx.signal` cancels a probe, and internal `ctx.probeTimeoutMs` allows controlled regression tests to shorten the default; it is not a user configuration option. Checks never probe credentials or send model requests. AI tools additionally require explicit Sec Hub executable configuration; the core enforces `--ai`. PHP requires both explicit executable configuration and a URL. SkillSpector requires a root `SKILL.md`, so it skips a generic repository rather than reporting a successful skill scan. Its MVP adapter always uses static analysis, including with `--ai`.

OSV's default Go call analysis is disabled, as is Rust call analysis; manifest dependency resolution is disabled. Dependency coverage therefore depends on the lockfiles/SBOMs available to OSV. No no-lockfile success option is added. Exit 1 means findings, while other nonzero codes fail execution. Group numeric CVSS ratings map to canonical severity bands; unrecognized ratings remain unknown and native vectors remain in evidence.

SkillSpector supports the current single-skill `issues` JSON shape. Active findings are preserved; suppressed native findings remain in the raw report. Native unsuccessful/incomplete scans raise an error carrying validated findings, so core reports failed coverage while retaining those findings. Exit 1 can mean a risk threshold, findings policy, or incomplete policy; the JSON coverage fields distinguish these.

Codex Security needs its native results outside every enclosing worktree. A small Node wrapper creates a private temporary parent, runs scan then export, and copies the native result tree into `artifacts/codex-security/codex-results` before cleanup. Per-step stdout/stderr are retained and also forwarded to the core's bounded streams. The wrapper forwards termination to the current child; children remain in the core process group. It preserves scan exit 1 after successful export and never exports after a failed scan. The canonical parser accepts the exported `codex-security.findings` v1.0 document, preserving occurrence IDs and code evidence. Findings are labelled reported, which does not assert runtime reproduction.

Open Code Review uses full-file `scan`, not a diff-only review. It can create native session metadata. Its general review comments can include non-security categories, which are preserved. Native partial/error statuses, budget exhaustion and review-limit warnings fail coverage while retaining findings. A successful review does not prove every vulnerability was found.

PHP2Shell performs a header/version heuristic and never proves a deployed build contains or lacks a fix. The checker's `unknown` exit 3 becomes a visible unknown finding; `potentially_vulnerable` exit 1 becomes a high-severity candidate; `ok` exit 0 yields no finding. Status/exit inconsistencies and invalid arguments fail. No redirect is followed; the native checker uses GET only as a fallback after HEAD receives 405/501.
