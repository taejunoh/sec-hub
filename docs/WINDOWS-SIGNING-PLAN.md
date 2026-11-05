# Sec Hub Windows x64 signing preparation

## Current package and PE inventory

Sec Hub Desktop 0.2.0 ships as a private, portable Windows x64 ZIP. Its manifest declares `publisherSigned: false`. `desktop/build.mjs` verifies the Electron archive, copies the runtime, renames `electron.exe` to `Sec Hub.exe` and `electron_wer.dll` to `Sec Hub_wer.dll`, and compiles the safe I/O helper from Sec Hub source. The Windows branch does not modify the renamed PE contents. [Desktop build](../desktop/build.mjs) · [0.2.0 verification record](../verification/desktop-scan-0.2.0/REPORT.md)

The public Electron 45.1.0 Windows ZIP and Google OSV Scanner 2.7.0 Windows executable were fetched without authentication. Their lengths and SHA-256 hashes matched the tracked locks. Header inspection found seven AMD64 PE32+ images in the Electron ZIP and one in the OSV release executable. The staged Windows helper below comes from the current build recipe. Confirm its machine type and all nine packaged paths on the next native Windows run. [Electron lock](../desktop/runtime-lock.json) · [OSV lock](../desktop/app/osv-lock.json) · [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

| Path relative to `Sec Hub/` | Provenance | Proposed treatment |
| --- | --- | --- |
| `Sec Hub.exe` | Electron `electron.exe` | Preserve exact bytes |
| `Sec Hub_wer.dll` | Electron `electron_wer.dll` | Preserve exact bytes |
| `d3dcompiler_47.dll`, `dxcompiler.dll`, `ffmpeg.dll`, `vk_swiftshader.dll`, `vulkan-1.dll` | Electron distribution | Preserve exact bytes |
| `resources/tools/osv/osv-scanner_windows_amd64.exe` | Google OSV Scanner 2.7.0 | Preserve exact bytes and runtime pin |
| `resources/core/src/native/windows-safe-io.exe` | Sec Hub source compiled with x64 MSVC | Eligible for Sec Hub signing |

The OSV pin is 58,999,296 bytes and SHA-256 `9964ed64ec9a387391eb4cc006ad5c531154821aef29b793e02c448de4686438`. `verifiedOSV()` checks the pinned size and the full-file digest before the desktop app uses the scanner. Authenticode changes those bytes. Keep the existing runtime check and retain the upstream hash in build metadata. A Windows Authenticode signature on the Electron executable would not seal the adjacent app resources or their `desktop-build.json`. A digest copied into that JSON would not provide an independent runtime trust anchor. [Runtime check](../desktop/app/tools.mjs)

## What to validate without signing credentials

1. On native Windows x64, build an unsigned prerelease from a clean checkout using the existing `desktop/build.mjs --target win32-x64` command. Keep build output and evidence in fresh directories outside the checkout. Use the existing workflow's x64 Visual Studio environment and user-profile temporary directory for packaged smoke. [Windows desktop workflow](../.github/workflows/desktop.yml)
2. Independently extract the ZIP into a new private temporary directory. Verify the ZIP and manifest against `SHA256SUMS.txt`, then compare all extracted file paths, byte lengths and SHA-256 hashes against `finalFiles`. Reject escaping paths, reparse points and case-insensitive duplicate paths. Run checks against the extracted ZIP and keep any fixtures or intentional mutations in separate copies.
3. Enumerate regular files recursively and classify PE images using `MZ`, a bounds-checked PE offset, `PE\0\0`, `Machine` and optional header magic. Check both PE content and executable suffixes such as `.exe`, `.dll`, `.node`, `.sys`, `.ocx` and `.cpl`. This catches a PE under an unexpected extension and a corrupt file at an expected PE path. Require the expected nine paths and AMD64 (`0x8664`) with PE32+ (`0x020b`). Log relative path, type, architecture, size, SHA-256 and origin. Treat changes to the inventory as a review requirement for future Electron or OSV upgrades.
4. Compare the seven extracted Electron PE hashes with their corresponding members from the pinned archive, applying only the two path renames. Compare OSV with the tracked pin. Compare the helper with `windowsSafeIO.sha256` and its entry in `finalFiles`. In ordinary CI, retain the existing `publisherSigned: false` classification. Verify a mismatch fails on a scratch copy by altering one byte of OSV, and verify an unexpected or missing PE fails inventory validation.
5. Run `node scripts/ci.mjs windows` with the packaged helper as the current workflow does, then `node --test desktop/test/*.test.mjs` and the existing `desktop/smoke.mjs` against the freshly extracted `Sec Hub.exe`. Require the scan to complete, reports to be ready and reflected in the catalog, and the app to shut down. Keep native build and smoke evidence on failure. Publish candidate distributables only after all checks pass. The documented 0.2.0 Windows run supplies a historical smoke baseline. [0.2.0 Windows evidence](../verification/desktop-scan-0.2.0/REPORT.md)

## Integration once a trusted signing route is approved

Keep the ordinary build and CI credential-free. For an approved signing run, use a separate protected Windows release job pinned to the reviewed commit, with a reviewed first-party path allowlist and a signer identity scoped to that job. Do not pass arbitrary paths or PR artifacts to the signing service. Record the staged inputs by hash and use a new isolated staging directory. Abort on signing or verification failure and publish only the verified result.

Sign the first-party helper before computing its packaged digest. If the release needs a trusted publisher on the download or application entry point, separately design a first-party installer or launcher and verify what it covers. The portable ZIP has no outer Authenticode signature and `Sec Hub.exe` currently remains an Electron binary. A helper signature alone is partial coverage. Express the verified scope in per-file release metadata so the portable ZIP and launcher are not described as Sec Hub publisher-signed based on the helper alone.

For approved signed PE files, require embedded Authenticode, the approved publisher identity and trust policy, SHA-256 and a trusted RFC 3161 timestamp. Verify on a clean Windows runner using the SDK's SignTool with `verify /pa /all /tw /v` and fail on a warning or nonzero exit. Check the expected publisher separately. Keep existing vendor bytes and signatures intact. Verify expected signatures and vendor hash equality again after extracting the final ZIP, then run the same packaged smoke on that extraction. Write `windowsSafeIO.sha256`, `finalFiles`, the manifest and `SHA256SUMS.txt` using the final packaged bytes. [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)

## Provider and distribution constraints

- Azure Artifact Signing requires a paid subscription. Free, trial and sponsored Azure subscriptions are unsupported. [Microsoft Artifact Signing FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq)
- SignPath Foundation covers qualifying open-source projects and limits its certificate to eligible first-party binaries. Its policy restricts vulnerability-scanning tools but explicitly excepts scanning software artifacts during development or testing. Eligibility for this private prerelease and the specific OSV use case is unconfirmed. [SignPath Foundation terms](https://signpath.org/terms)
- Microsoft Store can sign an MSIX or AppX after certification. That would be a separate package and distribution route. Store MSI and EXE submissions require publisher signatures. [Microsoft Store signing FAQ](https://learn.microsoft.com/en-us/windows/apps/publish/faq/get-started-with-the-microsoft-store)

This preparation verified the public upstream pins and PE headers. The proposed Windows inventory gate, new native smoke run and trusted signing remain pending.
