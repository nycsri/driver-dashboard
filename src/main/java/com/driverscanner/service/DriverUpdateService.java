package com.driverscanner.service;

import com.driverscanner.model.Driver;
import com.driverscanner.model.UpdateResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Triggers driver updates silently via Windows Update (PSWindowsUpdate module).
 * Requires: PSWindowsUpdate module, Administrator privileges.
 *
 * Install PSWindowsUpdate (run as Admin):
 *   Install-Module -Name PSWindowsUpdate -Force
 */
@Service
public class DriverUpdateService {

    private static final Logger log = LoggerFactory.getLogger(DriverUpdateService.class);

    private final AntivirusService antivirusService;
    private final DriverBackupService backupService;
    private final OemUpdateService oemUpdateService;

    @Autowired
    public DriverUpdateService(AntivirusService antivirusService, DriverBackupService backupService,
                               OemUpdateService oemUpdateService) {
        this.antivirusService = antivirusService;
        this.backupService = backupService;
        this.oemUpdateService = oemUpdateService;
    }

    record ProcessOutput(int exitCode, String output) {}

    /**
     * Firmware devices cannot be backed up via pnputil (no INF package) and must
     * go through OEM tooling.
     */
    public static boolean isFirmware(Driver driver) {
        return "Firmware".equals(driver.getDeviceClass())
            || (driver.getDeviceName() != null
                && driver.getDeviceName().toUpperCase().startsWith("MICROSOFT UEFI"));
    }

    public UpdateResult triggerUpdate(Driver driver, boolean forceWithoutBackup) {
        return triggerUpdate(driver, true, forceWithoutBackup);
    }

    /**
     * Triggers a silent driver update for the given driver via PSWindowsUpdate.
     *
     * backup=false is the user's explicit choice to skip the backup. With backup=true the
     * current driver INF is exported first (or a recent backup reused); if that fails and
     * forceWithoutBackup is false, returns requiresConfirmation=true and installs nothing.
     */
    public UpdateResult triggerUpdate(Driver driver, boolean backup, boolean forceWithoutBackup) {
        log.info("Triggering update for: " + driver.getDeviceName());

        if (isFirmware(driver)) {
            return oemUpdateService.triggerFirmwareUpdate(driver);
        }

        // Virtual Windows kernel components (WAN Miniport, etc.) have no INF package
        // and cannot be updated via PSWindowsUpdate or pnputil.
        if (isVirtualWindowsDriver(driver)) {
            log.info("Skipping virtual Windows driver (no INF, not updatable): " + driver.getDeviceName());
            return new UpdateResult(driver.getDeviceId(), false,
                driver.getDeviceName() + " is a built-in Windows component and cannot be updated.");
        }

        String backupPath = backup ? backupService.findRecentBackup(driver) : null;
        if (!backup) {
            log.info("User chose to update " + driver.getDeviceName() + " without a backup.");
        } else if (backupPath != null) {
            log.info("Recent backup found for " + driver.getDeviceName() + " at " + backupPath + " - skipping new backup.");
        } else {
            try {
                backupPath = backupService.backupDriver(driver);
                log.info("Driver backed up to: " + backupPath);
            } catch (Exception e) {
                if (!forceWithoutBackup) {
                    log.warn("Backup failed for " + driver.getDeviceName() + ": " + e.getMessage()
                        + " - halting; user confirmation required to proceed without backup.");
                    return UpdateResult.awaitingConfirmation(driver.getDeviceId(), e.getMessage());
                }
                log.warn("Backup failed but user approved proceeding without backup: " + e.getMessage());
            }
        }

        oemUpdateService.ensurePSWindowsUpdate();
        // Lookup order: UpdateID, then KB, then device-name title regex (see WindowsUpdateLookup).
        String psCmd = WindowsUpdateLookup.buildInstallScript(driver);

        try {
            ProcessOutput ps = runPowerShell(psCmd);
            int exitCode = ps.exitCode();
            String fullOutput = ps.output();
            log.info("PSWindowsUpdate output for '{}':\n{}", driver.getDeviceName(), fullOutput.trim());

            // PSWindowsUpdate often prints status lines before our marker — scan line by line.
            String successLine = null;
            boolean sawNone = false;
            for (String line : fullOutput.split("\n")) {
                String t = line.trim();
                if (t.startsWith("SUCCESS")) { successLine = t; break; }
                if (t.equals("NONE"))        { sawNone = true; }
            }

            if (fullOutput.contains("run an elevated") || fullOutput.contains("AccessDenied")
                    || fullOutput.contains("PermissionDenied")
                    || fullOutput.contains("Administrator rights are required")) {
                log.error("Update for '{}' requires elevation. Full output:\n{}", driver.getDeviceName(), fullOutput.trim());
                return new UpdateResult(driver.getDeviceId(), false,
                    "Administrator rights required to install updates. Restart the application as Administrator.");
            }

            if (fullOutput.contains("not recognized") || fullOutput.contains("CouldNotAutoloadMatchingModule")
                    || fullOutput.contains("module could not be loaded")) {
                log.warn("PSWindowsUpdate unavailable for '{}' — falling back to pnputil. Output:\n{}", driver.getDeviceName(), fullOutput.trim());
                return triggerPnpUtilScan();
            }

            if (exitCode != 0 && successLine == null) {
                log.error("PowerShell exited {} for '{}'. Output:\n{}", exitCode, driver.getDeviceName(), fullOutput.trim());
                return new UpdateResult(driver.getDeviceId(), false,
                    "PowerShell exited with code " + exitCode + ". Run as Administrator?");
            }

            if (successLine != null) {
                // Scan the backup (our files, not locked) rather than the WU cache
                // (which wuauserv holds locked while staging the install).
                String avSuffix = "";
                if (backupPath != null) {
                    AntivirusService.ScanResult av = antivirusService.scanPath(backupPath);
                    if (av.error())       log.warn("Antivirus scan of backup could not complete: {}", av.message());
                    else if (!av.clean()) log.error("Antivirus ALERT in driver backup {}: {}", backupPath, av.message());
                    else                  log.info("Antivirus backup scan clean: {}", av.message());
                    avSuffix = av.error()  ? " | AV: scan error (check manually)"
                             : av.clean()  ? " | AV: clean"
                                          : " | AV ALERT: " + av.message();
                }
                return new UpdateResult(driver.getDeviceId(), true,
                    "Update installed: " + successLine.replace("SUCCESS: ", "") + avSuffix,
                    backupPath);
            }

            if (sawNone) {
                return new UpdateResult(driver.getDeviceId(), false,
                    "No matching update found in Windows Update catalog.");
            }

            log.error("Unrecognised PSWindowsUpdate output for '{}':\n{}", driver.getDeviceName(), fullOutput.trim());
            return new UpdateResult(driver.getDeviceId(), false,
                "Unexpected result: " + fullOutput.trim());

        } catch (Exception e) {
            log.error("Update failed for '{}'", driver.getDeviceName(), e);
            return new UpdateResult(driver.getDeviceId(), false,
                "Exception during update: " + e.getMessage());
        }
    }

    /**
     * Uses pnputil to scan and apply all available driver updates from Windows Update.
     * Broader than per-device update — applies all available driver updates.
     */
    public UpdateResult triggerPnpUtilScan() {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                "pnputil.exe", "/scan-devices"
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                return new UpdateResult("ALL", true, "pnputil /scan-devices completed: " + output.toString().trim());
            } else {
                return new UpdateResult("ALL", false, "pnputil failed with code " + exitCode);
            }

        } catch (Exception e) {
            return new UpdateResult("ALL", false, "pnputil error: " + e.getMessage());
        }
    }

    ProcessOutput runPowerShell(String script) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
            "powershell.exe", "-NonInteractive", "-NoProfile",
            "-ExecutionPolicy", "Bypass", "-Command", script
        );
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        return new ProcessOutput(process.waitFor(), output.toString());
    }

    private boolean isVirtualWindowsDriver(Driver driver) {
        String name = driver.getDeviceName();
        if (name == null) return false;
        String upper = name.toUpperCase();
        return upper.startsWith("WAN MINIPORT")
            || upper.startsWith("MICROSOFT KERNEL")
            || upper.startsWith("NDIS")
            || upper.startsWith("RAS");
    }

    private String escapeForPowerShell(String input) {
        return input.replace("'", "''").replace("\"", "`\"");
    }
}
