# Driver Dashboard

A Spring Boot web application for Windows that inventories installed device drivers, detects which ones have newer versions available through Windows Update, and can install updates, back up drivers beforehand, and roll them back. Firmware is checked through the machine vendor's own update tool. A single-page dashboard served by the app is the user interface.

> ## DISCLAIMER - USE AT YOUR OWN RISK
>
> This software is provided "as is", without warranty of any kind, express or implied.
>
> Installing or rolling back device drivers, and especially BIOS/UEFI firmware, can render a system unbootable, unstable or unusable, and can cause data loss. This application runs with Administrator privileges and executes PowerShell, `pnputil` and OEM vendor tools on your machine.
>
> The authors and contributors accept no liability for any damage, data loss or other consequence arising from the use of this software.
>
> - Create a full system backup and a System Restore point before using it.
> - Test on a non-critical machine first.
> - This project is not affiliated with or endorsed by Microsoft, Dell, HP or Lenovo.
> - You are responsible for complying with your device's warranty and your organisation's policies.

## Features

- **Driver scan**: enumerates drivers via WMI (`Win32_PnPSignedDriver`), merged with each device's hardware and compatible IDs from `Win32_PnPEntity`.
- **Update detection**: one query to the Windows Update Agent (`Microsoft.Update.Session` COM API) lists applicable, not-installed driver updates. Installed drivers are matched to them by hardware ID, then compared by numeric version and date.
- **Date fallback**: only when the Windows Update Agent is unavailable, a driver dated more than 24 months ago is flagged `STALE` (estimate only).
- **Firmware**: drivers of class `Firmware` are checked through the OEM tool, once per scan: Dell Command Update, Lenovo Thin Installer or HP Image Assistant. If the tool is not installed, the check falls back to Windows Update.
- **Update with backup prompt**: before updating, the dashboard asks whether to back up the current driver (`pnputil /export-driver`). A backup younger than `driver.backup.recent-days` is reused. If the backup fails, nothing is installed until you explicitly confirm updating without one.
- **Verification**: after a successful update the device is rescanned and its status recomputed. An unchanged version with a reboot message becomes `PENDING_REBOOT`; an unchanged version otherwise becomes `UPDATE_FAILED`.
- **Rollback**: re-installs the backed-up INF (`pnputil /add-driver ... /install`). The backup path must lie inside that device's own backup folder.
- **Antivirus scan of backups**: after a successful update, the backup folder is scanned with Windows Defender (`MpCmdRun.exe`, custom scan). The result is appended to the update message and logged; it does not block or undo the update. Tool errors are reported separately from detected threats.
- **Scheduled scan**: a full scan runs daily (default 02:00, configurable).
- **Honest failure state**: if the Windows Update query fails, drivers are marked `UNKNOWN` rather than reported as up to date.
- Built-in Windows components (WAN Miniport, Microsoft Kernel, NDIS, RAS) are shown as up to date and are not updatable.

## Architecture

```
Browser (static dashboard, index.html)
    |
    v
Spring Boot REST API (DriverController, port 8080)
    |
    +-- DriverOrchestrationService      scan coordination, in-memory driver store, post-update status
    |     +-- DriverScannerService          PowerShell + WMI (Win32_PnPSignedDriver / Win32_PnPEntity)
    |     +-- WindowsUpdateCatalogService   Windows Update Agent query (PowerShell COM)
    |     |     +-- CatalogMatcher, VersionComparator   hardware-ID match, version/date comparison
    |     |     +-- OemUpdateService                    firmware: Dell / Lenovo / HP tools, WU fallback
    |     +-- (scan results cached in memory)
    |
    +-- DriverUpdateService             install: PSWindowsUpdate (WindowsUpdateLookup builds the script),
    |     |                             pnputil fallback, OEM tools for firmware
    |     +-- DriverBackupService           pnputil export / re-install, backup lookup and path confinement
    |     +-- AntivirusService              Windows Defender scan of the backup
    |
    +-- ScheduledDriverScanService      daily full scan (cron)
```

## Prerequisites

- Windows 10 or 11
- JDK 17 (`java.version` in `pom.xml`)
- Maven 3.x (Spring Boot 3.2.0 parent)
- Windows PowerShell (`powershell.exe`) and `pnputil.exe`, both present on a standard install
- Optional: the OEM tool for firmware checks (default install paths):
  - Dell Command Update (`C:\Program Files\Dell\CommandUpdate\dcu-cli.exe`)
  - Lenovo Thin Installer (`C:\Program Files (x86)\Lenovo\ThinInstaller\ThinInstaller.exe`)
  - HP Image Assistant (`C:\Program Files\HP\HP Image Assistant\HPImageAssistant.exe`, or the `Program Files (x86)` equivalent)
- Optional: Windows Defender for the backup scan (`C:\Program Files\Windows Defender\MpCmdRun.exe`)
- The PSWindowsUpdate PowerShell module is used for installing updates. The app tries to install it automatically (see Security notes).

## Build and run

```powershell
mvn clean package
java -jar target\driver-dashboard-1.0.0.jar
```

Start the application from an elevated (Administrator) shell; driver installs, `pnputil` and firmware tools require it. Then open http://localhost:8080.

## Configuration

Set in `src/main/resources/application.properties`, or override on the command line (for example `--driver.scan.schedule="0 0 3 * * ?"`).

| Key | Default | Meaning |
|-----|---------|---------|
| `server.port` | `8080` | HTTP port. |
| `spring.application.name` | `driver-dashboard` | Application name. |
| `spring.cache.type` | `simple` | In-memory Spring cache. |
| `logging.level.com.driverscanner` | `INFO` | Log level for application code. |
| `driver.scan.schedule` | `0 0 2 * * ?` | Spring cron (sec min hour day month weekday) for the daily scan. |
| `driver.backup.recent-days` | `7` | A backup younger than this is reused instead of exporting a new one. |
| `driver.backup.root` | `${LOCALAPPDATA:}\DriverDashboard\Backups` | Backup folder, laid out as `<root>\<deviceId>\<timestamp>`. Startup fails if `LOCALAPPDATA` is unset and no absolute path is given. |
| `driver.scan.ps-timeout-seconds` | `300` | Seconds before the Windows Update query PowerShell process is killed. |

## API

Base path: `/api/drivers`. `{deviceId}` is the stable hash returned in the `deviceId` field of each driver.

| Method | Path | Body | Description |
|--------|------|------|-------------|
| GET | `/api/drivers` | - | Cached drivers from the last scan; empty before the first scan. |
| POST | `/api/drivers/scan` | - | Full scan. Returns `total`, `stale`, `upToDate`, `unknown` counts and `drivers`. Can take minutes. 500 with `error` on failure. |
| POST | `/api/drivers/{deviceId}/update` | optional `{"backup": true\|false, "forceWithoutBackup": true}` | Update one device. `backup` defaults to true; `false` skips the backup by explicit choice. 200 with an `UpdateResult` (`success`, `message`, `backupPath`); 404 if the device is unknown; 409 if the backup failed and `forceWithoutBackup` is not set (response has `requiresConfirmation: true` and `backupError`; nothing was installed). |
| POST | `/api/drivers/scan-all-devices` | - | Runs `pnputil /scan-devices`. Machine-wide, not per device. |
| GET | `/api/drivers/{deviceId}/backup-status` | - | `hasRecentBackup`, `backupPath`, `timestamp`, `firmware`. Firmware never has a backup. 404 if unknown. |
| POST | `/api/drivers/{deviceId}/rollback` | `{"backupPath": "<path>"}` | Restore a backup. 400 if `backupPath` is missing or outside the device's backup folder; 500 on `pnputil` failure. On success the driver status is reset to `UNKNOWN` until the next scan. |

## Staleness detection and status values

1. The Windows Update Agent is queried once per scan for applicable driver updates not yet installed.
2. Each installed driver is matched to an update by hardware ID. A newer numeric version, or a newer date when no version is exposed, marks it `STALE`.
3. Only if the Windows Update Agent is unavailable does the 24-month date rule apply.
4. If the query fails or times out, affected drivers are `UNKNOWN`.
5. Firmware is judged by the OEM tool's exit code instead, once per scan.

| Status | Meaning |
|--------|---------|
| `UP_TO_DATE` | No newer update found (or built-in Windows component). |
| `STALE` | A newer update is available (or, in fallback mode, the driver is over 24 months old). |
| `UNKNOWN` | Could not be determined: Windows Update query failed, OEM tool inconclusive, rescan could not verify an update, or just rolled back. |
| `UPDATING` | An update is in progress. |
| `UPDATE_FAILED` | The update failed, or reported success but the installed version did not change. |
| `PENDING_REBOOT` | Update installed; a reboot is required for it to take effect. |

## Security notes

- **There is no authentication or authorization.** The app is intended for local use on a single machine.
- **Bind address:** `application.properties` does not set `server.address`, so the embedded server uses the Spring Boot default and listens on all network interfaces (port 8080), not only localhost. Anyone who can reach the port can trigger scans, driver and firmware updates, and rollbacks. Do not expose port 8080 to a network; use a host firewall rule or add `server.address=127.0.0.1` yourself. Run it only on trusted machines and networks.
- **Administrator privileges:** the process must be elevated, so any request it accepts runs with Administrator rights, including PowerShell, `pnputil` and OEM tool invocations.
- **Runtime module install:** before the first update, if the PSWindowsUpdate module is missing, the app runs `Install-Module PSWindowsUpdate -Scope CurrentUser` against the PowerShell Gallery, which may prompt to trust the repository or install the NuGet provider. PowerShell is launched with `-ExecutionPolicy Bypass`.
- Rollback is restricted to paths inside the device's own backup folder.

## Known limitations

- Windows only.
- Windows Update Agent COM behaviour and OEM tool exit-code handling were implemented from vendor and Microsoft documentation and not verified on every OEM or Windows build.
- The Dell and Lenovo firmware checks have not been verified on real hardware.
- The automated tests do not run real PowerShell, `pnputil` or OEM tools.
- Driver state is held in memory; it is lost on restart until the next scan.
- Backups use `pnputil /export-driver`, so firmware and built-in components cannot be backed up or rolled back.

## Project structure

```
pom.xml
src/main/java/com/driverscanner/
  DriverDashboardApplication.java
  controller/
    DriverController.java              REST endpoints
  model/
    Driver.java                        driver entity and Status enum
    UpdateResult.java                  update outcome, backup confirmation flags
  service/
    DriverScannerService.java          WMI inventory via PowerShell
    WindowsUpdateCatalogService.java   Windows Update Agent query, status assignment
    CatalogMatcher.java                hardware-ID matching of updates to drivers
    VersionComparator.java             numeric version comparison
    WindowsUpdateLookup.java           builds the install script (UpdateID, KB, then title)
    OemUpdateService.java              Dell / Lenovo / HP firmware tools, PSWindowsUpdate bootstrap
    DriverUpdateService.java           update execution, pnputil scan
    DriverBackupService.java           driver export, reuse, rollback, path confinement
    AntivirusService.java              Windows Defender scan of backups
    DriverOrchestrationService.java    scan coordination, driver store, post-update status
    ScheduledDriverScanService.java    daily scan
src/main/resources/
  application.properties
  static/index.html                    dashboard UI
src/test/java/com/driverscanner/       unit tests
```

## Contributing

Issues and pull requests are welcome. For bug reports include your Windows version, the OEM, and the relevant log output, with any machine-specific identifiers removed.
