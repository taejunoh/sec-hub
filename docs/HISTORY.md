# Release and verification history

For current setup and release information, start at the [README](../README.md).

## 0.3.1 source and seven-tool validation

On October 29, 2026, validation combined results from five CLI integrations with Cloudflare and Anthropic native runs. All seven integrations met the verification criteria for that run. The aggregate had 16 entries, including six reported findings and ten candidates. Its one high-severity Anthropic result remained a static candidate. The run did not include dynamic verification.

The local Node 24 suite passed 524 of 528 tests with four skips. Hosted CI passed all six jobs across macOS, Ubuntu, and Windows on Node 22 and 24.

## 0.3.0 hosted verification

Hosted CI passed all six platform and runtime jobs. Package smoke tests used synthetic scanners and made no provider calls.

## 0.2.4 workbench

The 0.2.4 package introduced the Korean and English developer workbench. The team verified an offline install on Node 24 and passed six installed browser checks. Package smoke used synthetic scanners, and the Anthropic workflow remained deferred.

## 0.2.3 process and file boundaries

This release added Windows child-process termination and trusted-ancestor checks, plus the Darwin ACL reader. The Node 24 regression suite passed 423 of 424 tests, with one native Windows skip. An offline install ran OSV Scanner, static SkillSpector, and the PHP2Shell checker against a controlled fixture. Those scans reported ten findings and left the fixture files unchanged. See the [historical platform and security details](REFERENCE.md#historical-platform-and-security-behavior-023).

## 0.2.2 security fixes

This release included fixes for retaining original text after a masking failure and for bypassing POSIX path validation. The Node 24 suite passed all 385 tests.

## Earlier integrations

Version 0.2.0 added execution support for the Cloudflare and Anthropic security workflows. Earlier 0.1.1 validation collected 13 results from five CLI tools, including authenticated Codex Security and Open Code Review runs. The automated suite passed all 68 tests.
