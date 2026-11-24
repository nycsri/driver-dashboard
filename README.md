# Driver Dashboard

A Spring Boot web app that scans Windows for stale drivers and updates them via Windows Update.

## Architecture

```
Browser (Dashboard UI)
    │
    ▼
Spring Boot REST API (port 8080)
    │
    ├── DriverScannerService      → PowerShell WMI (Win32_PnPSignedDriver)
    ├── WindowsUpdateCatalogService → PSWindowsUpdate module
    └── DriverUpdateService       → Install-WindowsUpdate / pnputil.exe
```

## Prerequisites

1. **Windows 10/11** (x64)
2. **Java 17+** (e.g. Eclipse Temurin)
3. **Maven 3.8+**
4. **PSWindowsUpdate PowerShell module** (required for catalog check + updates):
   ```powershell
   # Run PowerShell as Administrator
   Install-Module -Name PSWindowsUpdate -Force -AllowClobber
   Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
   ```
5. **Run the app as Administrator** (required for driver installs and pnputil)

## Build & Run

```bash
# Build
mvn clean package -DskipTests

# Run (as Administrator!)
java -jar target/driver-dashboard-1.0.0.jar
```

Open browser: http://localhost:8080

## API Endpoints

| Method | Path                             | Description                          |
|--------|----------------------------------|--------------------------------------|
| GET    | /api/drivers                     | List cached drivers (last scan)      |
| POST   | /api/drivers/scan                | Run full WMI scan + catalog check    |
| POST   | /api/drivers/{deviceId}/update   | Update a specific driver             |
| POST   | /api/drivers/scan-all-devices    | Run `pnputil /scan-devices`          |

## Staleness Detection

Drivers are checked against the **Windows Update catalog** via the PSWindowsUpdate
`Get-WindowsUpdate -Category 'Drivers'` command.

Fallback: if PSWindowsUpdate is unavailable, any driver with a date older than
**24 months** is flagged as stale.

## Update Mechanism

Uses `Install-WindowsUpdate -AcceptAll -AutoReboot:$false` (no forced reboots).
Some driver updates may require a manual reboot to take effect.

## Project Structure

```
src/main/java/com/driverscanner/
├── DriverDashboardApplication.java
├── controller/
│   └── DriverController.java          # REST endpoints
├── model/
│   ├── Driver.java                    # Driver entity + Status enum
│   └── UpdateResult.java
└── service/
    ├── DriverScannerService.java      # WMI via PowerShell
    ├── WindowsUpdateCatalogService.java # PSWindowsUpdate catalog check
    ├── DriverUpdateService.java       # Silent update trigger
    └── DriverOrchestrationService.java # Coordinates scan + check
```

## Notes

- Scanning 100–300 drivers with catalog checks can take **60–120 seconds**.
- The dashboard polls no background jobs — scans are triggered manually.
- Driver updates are non-destructive: `-AutoReboot:$false` prevents surprise reboots.
- Some OEM drivers (NVIDIA, Intel) may be better updated via vendor tools.
