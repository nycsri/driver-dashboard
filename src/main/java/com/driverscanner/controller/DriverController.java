package com.driverscanner.controller;

import com.driverscanner.model.Driver;
import com.driverscanner.model.UpdateResult;
import com.driverscanner.service.DriverBackupService;
import com.driverscanner.service.DriverOrchestrationService;
import com.driverscanner.service.DriverUpdateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/drivers")
public class DriverController {

    @Autowired private DriverOrchestrationService orchestration;
    @Autowired private DriverUpdateService updateService;
    @Autowired private DriverBackupService backupService;

    /**
     * GET /api/drivers
     * Returns the last cached driver list. Empty if no scan has run yet.
     */
    @GetMapping
    public List<Driver> listDrivers() {
        return orchestration.getCachedDrivers();
    }

    /**
     * POST /api/drivers/scan
     * Triggers a full WMI scan + Windows Update catalog check.
     * Can take 30–120 seconds depending on number of drivers.
     */
    @PostMapping("/scan")
    public ResponseEntity<?> triggerScan() {
        try {
            List<Driver> drivers = orchestration.runFullScan();
            return ResponseEntity.ok(Map.of(
                "total", drivers.size(),
                "stale", drivers.stream().filter(d -> d.getStatus() == Driver.Status.STALE).count(),
                "upToDate", drivers.stream().filter(d -> d.getStatus() == Driver.Status.UP_TO_DATE).count(),
                "unknown", drivers.stream().filter(d -> d.getStatus() == Driver.Status.UNKNOWN).count(),
                "drivers", drivers
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * POST /api/drivers/{deviceId}/update
     * Triggers a silent driver update via PSWindowsUpdate for the given device.
     *
     * Optional body: { "forceWithoutBackup": true }
     * If backup fails and forceWithoutBackup is absent/false, returns HTTP 409 with
     * requiresConfirmation=true. Re-send with forceWithoutBackup=true to approve
     * proceeding without a backup.
     */
    @PostMapping("/{deviceId}/update")
    public ResponseEntity<UpdateResult> updateDriver(
            @PathVariable String deviceId,
            @RequestBody(required = false) Map<String, Object> body) {
        Driver driver = orchestration.getDriver(deviceId);
        if (driver == null) {
            return ResponseEntity.notFound().build();
        }

        boolean forceWithoutBackup = body != null
            && Boolean.TRUE.equals(body.get("forceWithoutBackup"));

        String versionBefore = driver.getDriverVersion();
        driver.setStatus(Driver.Status.UPDATING);
        orchestration.putDriver(deviceId, driver);

        UpdateResult result = updateService.triggerUpdate(driver, forceWithoutBackup);

        if (result.isRequiresConfirmation()) {
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Backup failed — awaiting user confirmation.");
            orchestration.putDriver(deviceId, driver);
            return ResponseEntity.status(409).body(result);
        }

        if (result.isSuccess()) {
            applyRescan(driver, deviceId, versionBefore, result);
        } else {
            driver.setStatus(Driver.Status.UPDATE_FAILED);
            driver.setStatusMessage(result.getMessage());
        }
        orchestration.putDriver(deviceId, driver);

        return ResponseEntity.ok(result);
    }

    private void applyRescan(Driver driver, String deviceId, String versionBefore, UpdateResult result) {
        Driver rescanned;
        try {
            rescanned = orchestration.rescanDriver(deviceId);
        } catch (Exception e) {
            rescanned = null;
        }
        if (rescanned == null) {
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Update reported success; could not verify by rescan.");
            return;
        }
        var resolution = DriverOrchestrationService.resolvePostUpdateStatus(
            versionBefore, rescanned, result.getMessage());
        rescanned.setStatus(resolution.status());
        rescanned.setStatusMessage(resolution.message());
        orchestration.putDriver(deviceId, rescanned);
        driver.setStatus(resolution.status());
        driver.setStatusMessage(resolution.message());
        driver.setDriverVersion(rescanned.getDriverVersion());
    }

    /**
     * POST /api/drivers/scan-all-devices
     * Runs pnputil /scan-devices to apply all available driver updates from Windows Update.
     */
    @PostMapping("/scan-all-devices")
    public ResponseEntity<UpdateResult> pnpUtilScanAll() {
        UpdateResult result = updateService.triggerPnpUtilScan();
        return ResponseEntity.ok(result);
    }

    /**
     * POST /api/drivers/{deviceId}/rollback
     * Rolls back a driver to the backed-up version.
     * Body: { "backupPath": "C:\\...\\DriverDashboard\\Backups\\...\\20240101_120000" }
     */
    @PostMapping("/{deviceId}/rollback")
    public ResponseEntity<?> rollbackDriver(
            @PathVariable String deviceId,
            @RequestBody Map<String, String> body) {
        String backupPath = body.get("backupPath");
        if (backupPath == null || backupPath.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "backupPath is required"));
        }
        try {
            backupService.rollbackDriver(backupPath);
            Driver driver = orchestration.getDriver(deviceId);
            if (driver != null) {
                driver.setStatus(Driver.Status.UNKNOWN);
                driver.setStatusMessage("Rolled back from backup: " + backupPath);
                orchestration.putDriver(deviceId, driver);
            }
            return ResponseEntity.ok(Map.of("success", true, "backupPath", backupPath));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(Map.of("error", "Rollback failed: " + e.getMessage()));
        }
    }
}
