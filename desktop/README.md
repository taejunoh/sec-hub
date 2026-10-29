# Sec Hub desktop viewer

The desktop app opens saved Sec Hub results. It does not start scans.

## Choose the download for your computer

- **Apple silicon Mac (arm64):** extract the macOS ZIP, then open `Sec Hub.app`.
- **Windows PC (x64):** extract the Windows ZIP, then open `Sec Hub.exe` from the extracted folder. Keep the other files beside the executable.

These are unsigned developer prereleases. macOS or Windows may show a security warning. No publisher certificate or Apple notarization is available. Do not disable security protections or remove quarantine to open the app. Intel Macs and Windows ARM are not supported by these downloads.

## Open saved results

1. Double-click the app. It opens the workbench with a clearly labeled synthetic example containing three findings. This is sample data, not a scan of your files.
2. To view your own saved results, choose **File → Open saved results folder** and select the folder containing them. The app reads existing results only; it does not run a scan. A folder may contain a valid run with zero findings. If the folder is empty or its results are invalid, the app explains the problem and keeps the current view open.
3. Choose **File → Show example** to return to the sample, or **File → Open in browser** to open the current view in your browser.
4. Choose **File → Quit** or close the window to stop the app.

No separate Node.js, scanner, provider account, or AI login is needed. The app includes its runtime. Windows supports viewing saved results; creating reports or running scans on Windows is not supported.
