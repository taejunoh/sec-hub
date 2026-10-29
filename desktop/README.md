# Sec Hub desktop viewer

Open saved Sec Hub results in a desktop window. This app does not run scans.

The [desktop 0.1.0 release page](https://github.com/taejunoh/sec-hub/releases/tag/desktop-v0.1.0) is planned to host the downloads after final package checks. The ZIP filenames will be:

- macOS Apple silicon (arm64): `sec-hub-desktop-0.1.0-darwin-arm64-prerelease.zip`
- Windows PC (x64): `sec-hub-desktop-0.1.0-win32-x64-prerelease.zip`

## Use the app

1. Download the ZIP for your computer from the release page and extract it. On Mac, open `Sec Hub.app`. On Windows, open `Sec Hub.exe` from the extracted folder and keep the adjacent files beside it.
2. The app opens a clearly labeled synthetic example with three findings. To view saved results, choose **File → Open saved results folder** and select the folder. The app reads existing results only; it does not start scans. A valid run with zero findings is accepted. If the folder is empty or invalid, the app explains the issue and keeps the current view open.
3. Choose **File → Show example** to return to the sample, **File → Open in browser** to open the current view in your browser, or **File → Quit** to close the app.

The sample is not a scan of your files. No separate Node.js, scanner, provider account, or AI login is needed; the app includes its runtime. Windows supports viewing saved results, not creating reports or running scans.

These are developer prereleases. The Mac app is ad-hoc signed for integrity checking; it has no Apple developer certificate or notarization. Windows has no Sec Hub publisher certificate. macOS or Windows may show a security warning. Do not disable security protections or remove quarantine to open the app. Intel Macs and Windows ARM are not supported by these downloads.
