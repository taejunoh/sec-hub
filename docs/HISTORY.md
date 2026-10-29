# Release and verification history

This page records earlier releases and validation scope. For current setup and the latest hosted CI result, start at the [README](../README.md).

## 0.3.0 package and hosted verification

The preserved 0.3.0 [package](../releases/sec-hub-local-0.3.0.tgz) and [manifest](../releases/sec-hub-local-0.3.0.manifest.json) were created from product source commit `23702f4d850cf9a6c58d51d5bbbfa66fba83cb88`. The archive SHA-256 is `b99ceaafb71c23fdb0da50d585baa180ca1e7d1a9adfd58e3fafd554b2178bdb`; it contains 47 payload files. The package was independently validated on test-only commit `caed284b9654304e5e25691aad4b2a00f1a9d5e4`. Later hosted workflow-dispatch run [40789138455](https://github.com/taejunoh/sec-hub/actions/runs/40789138455) passed all six matrix jobs on head `4784a3ebe59fbf1bed547cef0246bc88820140e2`; its package-smoke payloads matched the preserved archive. See the [0.3.0 package report](../verification/release-0.3.0/REPORT.md) and [hosted CI acceptance report](../verification/ci-after-budget-2026-10-28/REPORT.md).

## Earlier release and security records

> At the 0.2.3 validation point, the release included Windows child-process termination boundary #31, trusted-ancestor boundary #40, and the Darwin ACL reader native helper. The release tarball was verified with an offline install into a fresh private npm project. The installed CLI ran OSV Scanner, static SkillSpector, and the PHP2Shell checker on a controlled fixture and recorded 10 findings without changing target files. The existing read-only dashboard was also checked feature by feature. The Anthropic workflow was deferred. This was not a security re-audit of Sec Hub itself or all seven tools. See the [0.2.3 package and verification report](../verification/release-0.2.3/REPORT.md).

> Version 0.2.2 stabilized fixes for Open Code Review 0.2.1 recheck findings #9 and #12 (high severity) and 19 medium-severity findings. Medium candidate #13 had already been disproven by the existing pinned official validator. The release passed the full Node 24 suite, **385/385**, including 57 new tests, as well as specification and independent quality review. See the [0.2.2 package](../releases/sec-hub-local-0.2.2.tgz), [22 finding decisions, fixes, and execution verification](../verification/release-0.2.2/REPORT.md), and [full test log](../verification/release-0.2.2/evidence/full-suite-node24.log).

The 0.2.2 release archive contains fixes and verification for high-severity findings #38 (original text remained after masking failure) and #41 (POSIX path validation bypass) from the earlier source checkout. The [original recheck records for 44 native candidates](../verification/ocr-0.2.1-assessment/REPORT.md) and [the two earlier fixes](../verification/high2-remediation/REPORT.md) are preserved. The 0.2.2 archive itself is unchanged, and its package does not contain the later #31/#40 fixes.

At the 0.2.3 metadata-change validation point, the Node 24 #31/#40 runtime regression suite passed 423 of 424 tests, with no failures and one native Windows skip. This was not a full-suite rerun after the 0.2.3 metadata change. See the [historical platform and security details](REFERENCE.md#historical-platform-and-security-behavior-023) and [#31/#40 local remediation report](../verification/high31-40-remediation/REPORT.md).

These historical platform restrictions and untested cases are detailed in the [reference section](REFERENCE.md#historical-platform-and-security-behavior-023).

The recorded Cloudflare run used static source-only quick coverage and produced two unconfirmed candidates with unknown severity. SARIF schema checks, credential-pattern checks, and HTML/evidence-link QA were completed. This did not verify all seven tools or confirm a dynamic exploit. A one-time follow-up for an Anthropic native canary, static checks, and final aggregation was scheduled for October 29, 2026 at 6:10 AM New York time in that historical note; it does not state the current automation status.

## 0.2.3 package layout

The 0.2.3 package included the CLI, runtime, examples, and README. Repository-maintenance tools under `scripts/` were available only from a repository checkout and were excluded from the installed package. The Darwin ACL reader binary, C source, and maintainer build script under `src/native/` were included; the build script served provenance/rebuild purposes and was not run or compiled by the CLI at runtime. The 0.2.2 release archive did not include this helper. Execution evidence remained under the repository's `verification/` directory.

## Historical build verification results

At the 0.1.1 validation point, the automated suite passed 68 tests, and five actual CLI scans collected 13 results from a validation codebase, including ChatGPT-authenticated Codex Security and Open Code Review. See the [combined HTML report](../verification/authenticated-five-combined/report.html) and [authentication and execution verification record](../verification/AUTHENTICATED-VALIDATION.md). The initial run and OCR budget-adjusted retry are retained with provenance; the combined report verifies the same-code hash and original results. Paths, models, and limits for the five tools are in `verification/authenticated-tools.config.json`. Credentials are not included in the package; another machine requires tool installation, login, and updated paths. Version 0.2.0 preserved this earlier verification history while adding actual-execution support for the official Cloudflare/Anthropic security skills. Any claim that all seven tools completed requires separate native evidence verification.

## 0.2.4 package

Version 0.2.4 contains the Korean/English developer workbench from source commit `ecf0c92f362e0854660162927d1d855e1f37644d`. Its tarball SHA-256 is `758c0e93364bff07b835fc04fb8ca79d04f2f66bc77ac40d3fb7e7f295448402`. It was checked with an offline install into a fresh private npm project on Node 24, and the installed browser checks passed 6/6. The CLI package smoke used only controlled fake scanners; it did not perform a new scanner/provider audit beyond displaying historical fixture data. The Anthropic workflow remained deferred. See the [0.2.4 package](../releases/sec-hub-local-0.2.4.tgz), [manifest](../releases/sec-hub-local-0.2.4.manifest.json), and [package verification report](../verification/release-0.2.4/REPORT.md).

## Private CI (Stage 2)

GitHub Actions run [40737123371](https://github.com/taejunoh/sec-hub/actions/runs/40737123371) completed successfully on source commit `8d2959862ce5fd72cb23ffac87880192a331caf0` on October 28, 2026: all six jobs passed across Linux, macOS, and Windows with Node 22/24. Linux and macOS ran the full supported suite and package smoke; Windows ran the declared portable subset plus native process-tree and fail-closed I/O cases. The [Stage 2 report and preserved evidence](../verification/private-ci/REPORT.md) records per-job counts, earlier failed attempts, and scope limits. This is the historical Stage 2 result, not the Stage 3 verification. Stage 3 later passed on source head `4784a3ebe59fbf1bed547cef0246bc88820140e2`; see the [current hosted CI acceptance report](../verification/ci-after-budget-2026-10-28/REPORT.md).

## Historical developer workbench preview at source point 6381c306

At source point `6381c306`, the saved-results screen had become a Korean/English developer workbench. The preview recorded for that source point was [http://127.0.0.1:64076/](http://127.0.0.1:64076/), and its verification scope and evidence are in the [developer workbench report](../verification/developer-workbench/REPORT.md). The released [0.2.3 package](../releases/sec-hub-local-0.2.3.tgz) predates those files and remains unchanged. This is a historical preview record, not a statement that the preview is currently running.

## Historical preview record from web-results UX verification

During earlier web-results UX verification, the checkout's results page was inspected locally by running `node bin/sec-hub.mjs serve --runs /absolute/path/to/sec-hub-runs` on loopback. The preview URL recorded at that time was [http://127.0.0.1:52557/](http://127.0.0.1:52557/); it is a record from that verification. The source point before that work was `2caf`. See the [web-results UX verification report](../verification/web-results-ux/REPORT.md) for the measurements, scope, and evidence from that time.
