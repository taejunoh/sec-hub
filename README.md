# Sec Hub

> **Current 0.3.0 package and CI status:** The preserved 0.3.0 archive is SHA-256 `b99ceaafb71c23fdb0da50d585baa180ca1e7d1a9adfd58e3fafd554b2178bdb`, created from product source `23702f4d850cf9a6c58d51d5bbbfa66fba83cb88`. Hosted workflow-dispatch run [40789138455](https://github.com/taejunoh/sec-hub/actions/runs/40789138455) passed all six CI matrix jobs on head `4784a3ebe59fbf1bed547cef0246bc88820140e2`; see the [hosted CI acceptance report](verification/ci-after-budget-2026-10-28/REPORT.md) for per-platform counts and evidence. Six CI jobs do not mean six security tools or seven integrations were scanned. The run used synthetic package-smoke execution only; it made no provider or Anthropic calls. The [0.3.0 package](releases/sec-hub-local-0.3.0.tgz) and [manifest](releases/sec-hub-local-0.3.0.manifest.json) are preserved.

> At the 0.2.3 validation point, the release included Windows child-process termination boundary #31, trusted-ancestor boundary #40, and the Darwin ACL reader native helper. The release tarball was verified with an offline install into a fresh private npm project. The installed CLI ran OSV Scanner, static SkillSpector, and the PHP2Shell checker on a controlled fixture and recorded 10 findings without changing target files. The existing read-only dashboard was also checked feature by feature. The Anthropic workflow was deferred. This was not a security re-audit of Sec Hub itself or all seven tools. See the [0.2.3 package and verification report](verification/release-0.2.3/REPORT.md).

> Version 0.2.2 stabilized fixes for Open Code Review 0.2.1 recheck findings #9 and #12 (high severity) and 19 medium-severity findings. Medium candidate #13 had already been disproven by the existing pinned official validator. The release passed the full Node 24 suite, **385/385**, including 57 new tests, as well as specification and independent quality review. See the [0.2.2 package](releases/sec-hub-local-0.2.2.tgz), [22 finding decisions, fixes, and execution verification](verification/release-0.2.2/REPORT.md), and [full test log](verification/release-0.2.2/evidence/full-suite-node24.log).

The 0.2.2 release archive contains fixes and verification for high-severity findings #38 (original text remained after masking failure) and #41 (POSIX path validation bypass) from the earlier source checkout. The [original recheck records for 44 native candidates](verification/ocr-0.2.1-assessment/REPORT.md) and [the two earlier fixes](verification/high2-remediation/REPORT.md) are preserved. The 0.2.2 archive itself is unchanged, and its package does not contain the later #31/#40 fixes.

At the 0.2.3 metadata-change validation point, the Node 24 full suite for the #31/#40 runtime regression checks passed 423 of 424 tests, with no failures and one native Windows skip. This was not a full-suite rerun after changing the 0.2.3 metadata. The `taskkill /T /F` behavior for #31 was checked on Darwin using an OS-boundary mock; it was not verified on an actual Windows host. Fix #40 enforces a permissions policy that trusts ancestor ownership by root (UID 0) or the current effective UID; directory swaps by a malicious process running under the same UID remain out of scope. See the [#31/#40 local remediation and verification report](verification/high31-40-remediation/REPORT.md).

These security boundaries affect supported behavior. On Windows, the safe filesystem helper fails closed on source and skill-root reads as well as report writes. On macOS, it rejects shared writable ancestors (including the fixed sticky `/tmp`) and ALLOW or unknown ACLs; checking ACLs at each ancestor increases startup, source inspection, and report-writing time. Linux mode/sticky policy was not tested on native Linux at that validation point. The Darwin ACL helper was run on macOS arm64; the universal x86_64 slice was not separately run natively.

The recorded Cloudflare run used static source-only quick coverage and produced two unconfirmed candidates with unknown severity. SARIF schema checks, credential-pattern checks, and HTML/evidence-link QA were completed. This did not verify all seven tools or confirm a dynamic exploit. A one-time follow-up for an Anthropic native canary, static checks, and final aggregation was scheduled for October 29, 2026 at 6:10 AM New York time in that historical note; it does not state the current automation status.

Sec Hub is a Node.js CLI that runs locally installed security scanners against a repository and saves results as JSON, SARIF 2.1.0, and a single HTML report. It requires Node.js 22 or later and uses only built-in modules.

Sec Hub does not automatically run scripts from the target repository or install tools. AI scanners require `--ai` and explicit configuration. Before running a tool that may upload code, review that tool's policy and configuration. Sec Hub does not apply automatic patches and does not describe child processes as sandboxed.

## Installation

```sh
cd outputs/sec-hub
npm install
node bin/sec-hub.mjs --help
```

`npm install` adds no runtime dependencies. If you want a global command, you may optionally run `npm link`. The basic invocation is `node bin/sec-hub.mjs`.

The 0.2.3 package contains the CLI, runtime, examples, and README. Repository-maintenance tools under `scripts/` are available only from a repository checkout and are excluded from the installed package. The Darwin ACL reader binary, C source, and maintainer build script under `src/native/` are included; the build script is for provenance/rebuild purposes and is not run or compiled by the CLI at runtime. The earlier 0.2.2 release archive does not include this helper. Execution evidence remains under the repository's `verification/` directory.

## Commands

Sec Hub supports five CLI adapters and two official agent workflows. The CLI adapters are Google OSV Scanner (`osv`), NVIDIA SkillSpector (`skillspector`), OpenAI Codex Security (`codex-security`), Alibaba Open Code Review (`open-code-review`), and OpenAI PHP2Shell Checker (`php2shell`). The official agent workflows are Cloudflare Security Audit (`cloudflare`) and Anthropic `/vuln-scan` (`anthropic`). Check `doctor` for availability and required credentials. It returns seven distinct IDs and marks manual import support for the two agents as a capability.

Check installation and configuration status:

```sh
node bin/sec-hub.mjs doctor /path/to/repository
node bin/sec-hub.mjs doctor /path/to/repository --json
```

Run a scan. By default, Sec Hub runs OSV Scanner and static-only SkillSpector when available; `--tools` selects tools explicitly.

```sh
node bin/sec-hub.mjs scan /path/to/repository
node bin/sec-hub.mjs scan /path/to/repository --tools osv,skillspector
node bin/sec-hub.mjs scan /path/to/repository --ai --tools codex-security,open-code-review --config ./sec-hub.config.json
node bin/sec-hub.mjs scan /path/to/repository --url http://127.0.0.1:8080 --tools php2shell --out ./sec-hub-runs
node bin/sec-hub.mjs scan /path/to/repository --timeout 180 --out ./sec-hub-runs
```

URL checks send requests only to the explicitly supplied HTTP(S) address. `--timeout` is in seconds. The run directory contains `run.json`, `report.html`, and `results.sarif`. Exit codes are `0` for a successful run with no findings, `1` when findings are present, and `2` for an error or incomplete run.

Regenerate a report from existing data:

```sh
node bin/sec-hub.mjs report ./sec-hub-runs/RUN_ID
node bin/sec-hub.mjs report ./sec-hub-runs/RUN_ID/run.json
```

Comparing two saved runs does not invoke scanners or use credentials. Each input must be a v1 saved-run JSON file, regardless of filename, or a run directory containing `run.json`.

```sh
node bin/sec-hub.mjs compare ./baseline-run ./current-run
node bin/sec-hub.mjs compare ./baseline-run/run.json ./current-run --fail-on critical --out ./comparison-report
```

The complete comparison result is written to stdout as key-ordered JSON. If `--out` is supplied, the same comparison is saved as `comparison.json` and `comparison.html` in a new directory. The output directory must be empty and must not overlap either input run. The input provenance includes file hashes and the path of each `run.json` that was read. Diagnostics are written to stderr.

The default for `--fail-on` is `high`; accepted values are `critical`, `high`, `medium`, `low`, `info`, `any`, and `none`. The gate evaluates only newly observed findings and findings whose severity increased. It exits `1` if a new result meets the selected threshold, and exits `2` when an `unknown` severity or incomplete comparison scope makes the result indeterminate. `any` blocks every new result regardless of severity; `none` disables the finding gate but still returns `2` for an incomplete scope. All comparison entries remain in the JSON and HTML reports.

`new` means that a result was not seen in the baseline run; it does not prove the result was newly introduced in the code. `candidate` and `reported` provenance is retained and is not promoted to `confirmed`. A result is classified as `resolved` when it is absent from the current run within a comparable scan scope. This does not confirm a patch or remediation. If a tool is missing, failed, or partial, or its identity is too weak to determine whether the result is absent, the result is marked `unobserved` and the comparison is incomplete. Existing high-severity results pass the new-only gate; an item that changes from lower to higher severity is evaluated as `regressed`.

Both runs must refer to the same absolute target path. If their saved revisions differ, each revision is shown and the comparison is still allowed. Dependency identity uses exact package/version and primary identifiers, so an alias change can appear as a new result and a missing result. Fallback line identity does not infer that a finding is the same vulnerability after lines move; this may create a separate new and unobserved entry. Duplicate occurrence counts are retained.

For CI comparisons, OSV alone can be used as the default profile. Add `skillspector` only when the target repository root contains `SKILL.md`. Completed OSV and SkillSpector checks can be compared against matching target scope. The Cloudflare quick profile is always partial, and PHP endpoint scope cannot be established from history alone; both cases return comparison exit code `2`. Unselected tools, failed checks, imported data, missing tools, or unknown scan contracts are not treated as complete scope. Therefore, an aggregate of six tools or an integration result with Anthropic pending cannot pass as a new complete seven-tool gate.

To inspect saved runs and comparisons in the read-only local dashboard, provide the absolute path to the selected runs root:

```sh
node bin/sec-hub.mjs serve --runs /absolute/path/to/sec-hub-runs
```

The default port `0` lets the operating system choose an available port. Open the printed `127.0.0.1` URL directly in a browser. `--port` also accepts decimal ports from 0 to 65535. The server binds only to loopback, and the browser calls the API only on the same loopback origin. In default read-only mode, the dashboard does not authenticate users; this is not public hosting or isolation from untrusted local users.

In default read-only mode, the dashboard reads only `run.json` and `comparison.json` at its root and files with those names directly inside each run directory, once at startup. It does not recurse into subdirectories, follow `raw/`, read source files, or follow stored paths. Restart the server after adding saved-run files; opt-in scan results are added only through the explicit Refresh results action. Limits include 512 directory entries, 128 artifacts, 20 MiB of JSON per artifact, and 64 MiB total input; the UI reports truncation or limit notices. The dashboard does not serve saved HTML reports.

A completed run is not a safety determination and does not prove that no vulnerabilities exist. Imported results are labeled “Imported · not run locally”; saved comparisons are labeled “Saved comparison · source scans not revalidated”. Candidate results are not promoted to confirmed, and `resolved` is not described as a confirmed fix. The browser runs the existing comparison engine in memory and does not write `comparison.json` or HTML reports. Comparison-gate exit values are `0` for passing the selected threshold in a complete comparison, `1` for a violation in a complete comparison, and `2` when scope is incomplete or the result is indeterminate. Gate results are response data and do not affect the server exit code. Stop the server with Ctrl+C or SIGTERM.

## Explicit web scan execution

Web execution is disabled by default. If `--execution-config` is omitted, the dashboard remains read-only and the execution API is unavailable. To allow scans, the operator must create a separate manifest and scanner configuration file and provide both paths as absolute paths.

```sh
node bin/sec-hub.mjs serve \
  --runs /absolute/path/to/sec-hub-runs \
  --execution-config /absolute/path/to/web-execution.config.json
```

See [web-execution.config.json](examples/web-execution.config.json) for the manifest format. Each target specifies a display name, an absolute target path, an existing Sec Hub scanner configuration file, allowed tool IDs, and optional limits. The allowed-tool list must be nonempty and contain no duplicates; the browser can select only a subset of that list. `ai` defaults to `false`; to approve an AI tool, the operator must explicitly set it to `true` for that target. Web execution does not support `anthropic`. If PHP2Shell is enabled, its scan URL is fixed in the manifest target and cannot be entered in the browser.

Execution mode is intended for a trusted local operator. The manifest and scanner configuration are validated at startup; restart the server to change paths or settings. Browser requests cannot change commands, paths, configuration, environment variables, timeouts, or AI consent. The loopback execution URL printed by the server contains a secret token that is valid only for that server session. Do not share the URL or copy it into logs, screenshots, or evidence. Restarting the server requires using the new session URL.

Only one scan can run at a time; there is no queue. Each server session allows at most 20 starts. The UI job states (`running`, `cancelling`, `cancelled`, `completed`, `failed`) are separate from scan `runStatus` (`completed`, `partial`, `failed`). For example, a job may be `completed` while its selected tool coverage is partial or findings exist. Progress shows the phase and completed-tool count; it does not show estimated percentages.

After report writing finishes, the operator must explicitly choose **Refresh results** to add the new run to the list and open it. Results are not refreshed automatically. If a new run exceeds the dashboard catalog limit, the UI says that no result link is available. Cancellation remains `cancelling` until cleanup of owned processes is confirmed. The execution panel is hidden in read-only mode.

Trust the scanners, configuration, Git, and target files running under the same OS user. This feature is not OS isolation from other processes under the same user and is not a sandbox for hostile code. Windows safe report writes remain fail closed, so writing scan reports on Windows is unsupported. See the [web-execution report](verification/web-execution/REPORT.md) for verified execution, cancellation, refresh scope, and release-gate limits.

Bridge guidance, export of the import contract, and result import:

```sh
node bin/sec-hub.mjs bridge cloudflare --out ./cloudflare-handoff
node bin/sec-hub.mjs bridge anthropic --out ./anthropic-handoff
node bin/sec-hub.mjs import cloudflare ./cloudflare-handoff/findings.json --target /path/to/repository --out ./sec-hub-import
node bin/sec-hub.mjs import anthropic ./anthropic-handoff/findings.json --target /path/to/repository --out ./sec-hub-import
```

These manual bridge/import commands remain supported separately from actual agent execution. Imported results have tool status `imported`; they are not local executions. Empty or unknown data shapes are rejected rather than interpreted as a safe no-result. Cloudflare supports the official native schema values `confirmed`, `needs_validation`, and `rejected`. `rejected` is retained in imported record counts but is not counted as a vulnerability finding. Anthropic supports only the documented Sec Hub JSON contract; Sec Hub does not claim support for upstream-specific output formats.

## Tool configuration

Configuration examples for all five adapters are in [examples/sec-hub.config.json](examples/sec-hub.config.json). They use installed executable names. Replace the PHP checker script path with the absolute path in your own clone. The examples contain no credentials.

A configuration file is read only when passed with `--config`. Sec Hub does not automatically read configuration files from the target repository. Each tool is configured with an executable and an argv prefix. Shell command strings are not supported.

```json
{
  "tools": {
    "osv": { "command": "osv-scanner", "args": [] },
    "skillspector": { "command": "skillspector", "args": [] },
    "codex-security": { "command": "cs", "args": [] },
    "open-code-review": { "command": "ocr", "args": [] },
    "php2shell": { "command": "node", "args": ["/absolute/path/to/php2shell-checker/skills/phpcheck-url/scripts/phpcheck.js"] }
  }
}
```

For the PHP checker, configure the script path after the Node executable. Configure AI tools with an executable and arguments in the same way, and pass `--ai`. Provide credentials directly in the environment required by each tool. Configuration files and inherited environment variables are not recorded in reports.

Optional `scanOptions` can set authentication method, model, and execution budget for AI scans only. The [five-tool configuration example with budget limits](examples/ai-tools.config.json) uses upstream login stores and contains no credentials. `args` remain the executable prefix; `scanOptions` are appended only to `scan`. They are not passed to version checks or Codex `export`. `--ai` is still required.

Codex options are `auth` (`chatgpt`, `api-key`, `auto`), `model` (a nonempty string), `effort` (`low`, `medium`, `high`, `xhigh`), `maxCost`, and `maxTimeMinutes` (positive numbers). OCR options are `provider`, `model` (a nonempty string), `maxTokensBudget`, `concurrency`, and `timeoutMinutes` (positive integers), plus `noPlan`, `noDedup`, and `noSummary` (booleans). Unknown options and patch/output-path overrides are rejected. Native budgets are enforced according to upstream policy; Sec Hub's `--timeout` applies separately.

OCR reserves estimated tokens for the following file before review, so it can skip a file even when actual usage is below the limit. In the synthetic fixture, a 20,000-token budget prevented the `server.mjs` batch, so the example uses 40,000. If `budget_exceeded` or a review-limit warning appears, the run is not considered complete even if it has zero findings.

The maintenance commands below under `scripts/` run only from a repository checkout. Installed packages do not include `scripts/`, its test helpers, or fixtures. To revalidate the five authenticated CLIs, first sign in with each upstream's official login command, then provide explicit configuration with updated install paths and a new absolute output path. This command makes real AI service calls.

```sh
node scripts/live-verify-five.mjs --config /absolute/ai-tools.config.json --out /absolute/new-verification-run
```

If needed, specify a Node 22+ executable with `--runtime /absolute/node`. The helper copies safe synthetic source and stale dependency metadata into `work/live-five-target-*`, checks localhost PHP response headers, and does not install or run target source. It selects the five tools explicitly and applies a 600-second limit to each. It records completion status, native output, regenerated reports, SARIF, and file SHA-256 hashes. Failures and partial results are preserved; the helper succeeds only if all five tools complete. New OCR session metadata is recorded in an additional file; any change to the existing source causes validation to fail. Git internal metadata is excluded from hashing. A controlled CLI in tests is not evidence of a real authenticated call.

To combine two runs when retrying only OCR during verification, use `scripts/combine-verified-runs.mjs --original /absolute/initial-run --retry /absolute/ocr-retry --out /absolute/new-combined-run`. This helper checks the same path and revision, the original target's before/after/current SHA-256, preserved native results, and original artifact hashes. It requires four tools to have completed and OCR to have failed in the initial run, followed by a successful retry with only OCR selected. The combined report identifies the `aggregate` source, both run IDs, and the original failure history; it does not represent the runs as one scan. The original run directories are not modified.

## Official security-skill workflows

Update the executable paths, official checkouts, and absolute private `workRoot` paths in the [seven-tool configuration example](examples/seven-tools.config.json) for your environment. The existing default tool selection stays the same. To select the two new workflows and make their cost explicit, specify `--tools cloudflare,anthropic` or all seven IDs. Adding only `--ai` expands the existing CLI selection.

```sh
node bin/sec-hub.mjs scan /path/to/repository --ai --tools cloudflare,anthropic --config /absolute/seven-tools.config.json --timeout 1200 --out /absolute/new-native-run
```

`agentOptions` is an allowlist. Common options are `skillRoot` and `workRoot` (absolute paths), `revision` (the 40-character official pin SHA), and `model`. Cloudflare supports `strategy` (`native-collab|supervised-codex-workers`, defaulting to the existing `native-collab`), `effort` (`low|medium|high|xhigh`), `profile: "quick"`, and `maxAgents` (default 10; at least 7 for `native-collab`, or at least 8 before execution for `supervised-codex-workers`: four recon workers, one planner, one hunter, one critic, and one reserved verifier). Anthropic supports `maxTurns` (positive integer, default 30), `maxBudgetUsd` (finite positive number, default 3), `mode: "vuln-scan"`, `single: true`, and `noScore: true`. Arbitrary prompts, patch settings, secret values, and unknown options are rejected. `command` and `args` remain the executable and argv prefix. Sec Hub uses the upstream CLI's login state; it does not read credential files or install tools.

Cloudflare runs the agent-neutral security-audit skill pinned at `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` through the Codex CLI. Existing `native-collab` requires evidence of actual native spawn/wait. The explicitly selected `supervised-codex-workers` is Sec Hub's implementation: a trusted supervisor runs independent read-only Codex processes and verifies four recon workers, planner/hunter waves, final critic, fresh verifier, and official-validator evidence. This is not claimed as Cloudflare's official Codex integration or as a verified run. The quick profile is static source review and does not claim dynamic exploit confirmation. Completion requires the required workflow stages, both official validators, and evidence/output for actual processes and role independence under the selected strategy. Anthropic invokes the official Claude Code `/vuln-scan --single --no-score` at pin `d3bea6b5793b5f3d59a75ebe69a58efa88383145`. This is static candidate review and differs from running the C/C++ Docker/gVisor/ASAN reference harness. Both workflows use a fresh source copy on a trusted runner and verify preservation of input source, native completion evidence, and result schema. Source modification or incomplete evidence is not marked complete.

The model-authored grouped exclusion catalog for `supervised-codex-workers` includes known IDs and unit references, then expands them to the existing full-coverage semantic validation and hunter map. Source-only and known-fixture policies remain in force and do not reduce semantic validation. The Codex `--output-schema` canary in recon checks only whether the provider accepts structured-output schemas; it is not source inspection or evidence for the full workflow. Each role has a separate schema, and the recon canary is not generalized to other roles. Malformed native JSON is rejected, not repaired automatically. Sec Hub does not invent source claims or automatically recover data. The planner is limited to 600 seconds, other roles to 300 seconds, and the overall run is bounded by the caller's remaining deadline and a maximum of 1800 seconds. A minimum `maxAgents` of 8 reserves roles; it does not guarantee sufficient execution budget. The default maximum of 10 may need to be raised explicitly for this work. The policy gate reads streamed text and can detect prohibited external SKILL content or stalled state early, but it does not isolate filesystem access. This workflow is not vendor-certified and provides source-only quick coverage.

A new scan omits both `preparationFrom` and `preparationSha256`. Only a previous run that completed all four recon tasks and the planner with native exit 0 and schema-supported output, then failed during host-ledger ordering, is eligible for preparation-stage recovery. For an explicit Cloudflare `strategy: "supervised-codex-workers"`, add both `preparationFrom: "/absolute/old-run/raw/cloudflare/execution-manifest.json"` and `preparationSha256: "<64 lowercase hex characters>"` containing the hash of that original manifest, then run the following command with a new output path. This is not manual import or a general resume. The earlier failed run is not modified. The target, pin, native settings (including the `maxAgents` budget), original artifact hashes, execution identity, source evidence, and current `preparePlan` are all revalidated. The five reused roles count toward the new budget; hunter, critic, and verifier run again. The receipt retains provenance across cohorts and does not represent them as one new run. Recursive chaining, reuse of later stages, native failure, or missing/tampered preparation evidence is rejected. The source-only quick/known-fixture and post-text policy-gate limits described above also apply.

```sh
node bin/sec-hub.mjs scan /path/to/repository --ai --tools cloudflare --config /absolute/preparation-reuse.config.json --timeout 1800 --out /absolute/new-preparation-run
```

JSON, HTML, and SARIF tool-execution records include mode, backend, source pin, static-review limits, and dynamic-validation status. Reports that combine separate runs retain aggregate provenance and original run history rather than presenting them as one run. Consult new verification records for how the existing five CLI results and the two workflows were checked and whether each actually completed.

To revalidate and combine the preserved five-CLI aggregate with new native runs, use the command below. `--agents` may be repeated to provide Cloudflare and Anthropic from separate run directories. All inputs must be absolute paths, and `--out` must be a new external directory. Each agent input must be an original local run whose selected tool actually completed; duplicate completed tools or failed runs are rejected. The helper rechecks target hashes, provenance, post-redaction hashes, and native-run evidence.

```sh
node scripts/verify-seven-tools.mjs --five /absolute/five-combined --agents /absolute/cloudflare-completed --agents /absolute/anthropic-completed --config /absolute/seven-tools.config.json --out /absolute/new-seven-verified
```

While Anthropic is deferred, the following command can combine only a Cloudflare run with actual completion evidence. It is an example and does not claim that a current Cloudflare run completed.

```sh
node scripts/verify-seven-tools.mjs --five /absolute/five-combined --agents /absolute/cloudflare-completed --config /absolute/seven-tools.config.json --out /absolute/new-six-partial --allow-partial
```

`--allow-partial` does not turn a missing agent into a completed one. If evidence for all six tools above is verified, the result is `verifiedIntegrations: 6`, `status: "partial"`, `verificationPassed: false`, and `pendingIntegrations: ["anthropic"]`, with exit code **2**. It is not labeled as seven-tool completion. Without this option, evidence of completion for both agents is required; exit code 0 and `verificationPassed: true` require all seven tools to be verified.

## Interpreting results

HTML reports show each tool's selected/completed/skipped/failed/imported status, scan scope, failure reason, and scope limits caused by tools that were not run. They distinguish `candidate`, `reported`, and `confirmed` provenance for findings. Zero findings after all checks complete does not prove that no vulnerabilities exist. In SARIF, `unknown` severity remains `level: none` with `properties.severity: unknown`.

OSV vulnerability-database lookups and SkillSpector's optional advisory lookup may use the network, so they are not fully offline scans. Codex Security and Open Code Review may upload code to their configured services. PHP2Shell Checker uses header/version heuristics for the specified URL. Review upstream documentation for warnings and network behavior from each tool. Secret detection is not a general-purpose secret scanner.

## External connections

- [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill) — Runs the pinned official audit skill through the Codex CLI and supports manual bridge import. It validates the official `skills/security-audit/report-schema.json` format.
- [Anthropic Defending Code Reference Harness](https://github.com/anthropics/defending-code-reference-harness) — The pinned repository uses the Apache-2.0 license and its README says it is not maintained. The included official Claude Code security skill runs static `/vuln-scan` mode. This does not run the separate C/C++ harness, and upstream implementations are not bundled in Sec Hub. Manual import retains the Sec Hub contract.

Export the import schemas and examples for either bridge with `node bin/sec-hub.mjs bridge <provider> --out <directory>`. This repository's examples are [Cloudflare](examples/cloudflare-bridge.json) and [Anthropic](examples/anthropic-bridge.json).

## Development

The repository test suite checks invocation arguments, parsing, normalization, reports, and import contracts. Passing mock/fixture tests alone does not show that an upstream security scanner actually ran. Check run records separately for evidence of real upstream execution.

```sh
node --test
```

## Historical build verification results

At the 0.1.1 validation point, the automated suite passed 68 tests, and five actual CLI scans collected 13 results from a validation codebase, including ChatGPT-authenticated Codex Security and Open Code Review. See the [combined HTML report](verification/authenticated-five-combined/report.html) and [authentication and execution verification record](verification/AUTHENTICATED-VALIDATION.md). The initial run and OCR budget-adjusted retry are retained with provenance; the combined report verifies the same-code hash and original results. Paths, models, and limits for the five tools are in `verification/authenticated-tools.config.json`. Credentials are not included in the package; another machine requires tool installation, login, and updated paths. Version 0.2.0 preserved this earlier verification history while adding actual-execution support for the official Cloudflare/Anthropic security skills. Any claim that all seven tools completed requires separate native evidence verification.

## 0.2.4 package

Version 0.2.4 contains the Korean/English developer workbench from source commit `ecf0c92f362e0854660162927d1d855e1f37644d`. Its tarball SHA-256 is `758c0e93364bff07b835fc04fb8ca79d04f2f66bc77ac40d3fb7e7f295448402`. It was checked with an offline install into a fresh private npm project on Node 24, and the installed browser checks passed 6/6. The CLI package smoke used only controlled fake scanners; it did not perform a new scanner/provider audit beyond displaying historical fixture data. The Anthropic workflow remained deferred. See the [0.2.4 package](releases/sec-hub-local-0.2.4.tgz), [manifest](releases/sec-hub-local-0.2.4.manifest.json), and [package verification report](verification/release-0.2.4/REPORT.md).

## Private CI (Stage 2)

GitHub Actions run [40737123371](https://github.com/taejunoh/sec-hub/actions/runs/40737123371) completed successfully on source commit `8d2959862ce5fd72cb23ffac87880192a331caf0` on October 28, 2026: all six jobs passed across Linux, macOS, and Windows with Node 22/24. Linux and macOS ran the full supported suite and package smoke; Windows ran the declared portable subset plus native process-tree and fail-closed I/O cases. The [Stage 2 report and preserved evidence](verification/private-ci/REPORT.md) records per-job counts, earlier failed attempts, and scope limits. This is the historical Stage 2 result, not the Stage 3 verification. Stage 3 subsequently passed on source head `4784a3ebe59fbf1bed547cef0246bc88820140e2`; see the [current hosted CI acceptance report](verification/ci-after-budget-2026-10-28/REPORT.md).

## Historical developer workbench preview at source point 6381c306

At source point `6381c306`, the saved-results screen had become a Korean/English developer workbench. The preview recorded for that source point was [http://127.0.0.1:64076/](http://127.0.0.1:64076/), and its verification scope and evidence are in the [developer workbench report](verification/developer-workbench/REPORT.md). The released [0.2.3 package](releases/sec-hub-local-0.2.3.tgz) predates those files and remains unchanged. This is a historical preview record, not a statement that the preview is currently running.

## Historical preview record from web-results UX verification

During earlier web-results UX verification, the checkout's results page was inspected locally by running `node bin/sec-hub.mjs serve --runs /absolute/path/to/sec-hub-runs` on loopback. The preview URL recorded at that time was [http://127.0.0.1:52557/](http://127.0.0.1:52557/); it is a record from that verification. The source point before that work was `2caf`. See the [web-results UX verification report](verification/web-results-ux/REPORT.md) for the measurements, scope, and evidence from that time.
