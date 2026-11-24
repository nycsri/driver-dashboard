package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

@Service
public class DriverOrchestrationService {

    private static final Logger log = Logger.getLogger(DriverOrchestrationService.class.getName());

    @Autowired private DriverScannerService scannerService;
    @Autowired private WindowsUpdateCatalogService catalogService;
    // In-memory store of last scan results (keyed by deviceId)
    private final Map<String, Driver> driverStore = new ConcurrentHashMap<>();

    /**
     * Full scan: enumerate all installed drivers, then check each against
     * Windows Update catalog for newer versions.
     */
    public List<Driver> runFullScan() throws Exception {
        log.info("Starting full driver scan...");
        List<Driver> drivers = scannerService.scanInstalledDrivers();

        // Single PowerShell invocation for all drivers; firmware routed to OEM tools
        catalogService.batchCheckForUpdates(drivers);

        // Refresh store
        driverStore.clear();
        drivers.forEach(d -> driverStore.put(d.getDeviceId(), d));

        log.info("Scan complete. Total: " + drivers.size() +
            ", Stale: " + drivers.stream().filter(d -> d.getStatus() == Driver.Status.STALE).count());
        return drivers;
    }

    public List<Driver> getCachedDrivers() {
        return new ArrayList<>(driverStore.values());
    }

    public Driver getDriver(String deviceId) {
        return driverStore.get(deviceId);
    }

    public void putDriver(String deviceId, Driver driver) {
        driverStore.put(deviceId, driver);
    }

    /** Rescans installed drivers and re-checks only the given device; null if it is no longer present. */
    public Driver rescanDriver(String deviceId) throws Exception {
        Driver fresh = scannerService.scanInstalledDrivers().stream()
            .filter(d -> deviceId.equals(d.getDeviceId()))
            .findFirst().orElse(null);
        if (fresh == null) {
            return null;
        }
        catalogService.batchCheckForUpdates(new ArrayList<>(List.of(fresh)));
        driverStore.put(deviceId, fresh);
        return fresh;
    }

    public record PostUpdateResolution(Driver.Status status, String message) {}

    public static PostUpdateResolution resolvePostUpdateStatus(String versionBefore, Driver rescanned,
                                                        String resultMessage) {
        String after = rescanned.getDriverVersion();
        if (!Objects.equals(versionBefore, after)) {
            return new PostUpdateResolution(rescanned.getStatus(),
                "Updated: " + versionBefore + " -> " + after);
        }
        if (resultMessage != null && resultMessage.toLowerCase().contains("reboot")) {
            return new PostUpdateResolution(Driver.Status.PENDING_REBOOT,
                "Update installed — reboot required to apply.");
        }
        return new PostUpdateResolution(Driver.Status.UPDATE_FAILED,
            "Update reported success but installed version unchanged");
    }
}
