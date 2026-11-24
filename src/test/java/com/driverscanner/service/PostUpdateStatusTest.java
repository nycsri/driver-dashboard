package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PostUpdateStatusTest {

    private static Driver rescanned(String version, Driver.Status status) {
        Driver d = new Driver("id1", "Dev", version, "2024-01-01", "P", "C");
        d.setStatus(status);
        return d;
    }

    @Test
    void versionChangedUsesRecheckStatusAndReportsTransition() {
        var r = DriverOrchestrationService.resolvePostUpdateStatus(
            "1.0", rescanned("2.0", Driver.Status.UP_TO_DATE), "ok");
        assertEquals(Driver.Status.UP_TO_DATE, r.status());
        assertEquals("Updated: 1.0 -> 2.0", r.message());
    }

    @Test
    void versionUnchangedWithRebootIsPendingReboot() {
        var r = DriverOrchestrationService.resolvePostUpdateStatus(
            "1.0", rescanned("1.0", Driver.Status.STALE), "Installed. Reboot required.");
        assertEquals(Driver.Status.PENDING_REBOOT, r.status());
        assertEquals("Update installed — reboot required to apply.", r.message());
    }

    @Test
    void versionUnchangedWithoutRebootFails() {
        var r = DriverOrchestrationService.resolvePostUpdateStatus(
            "1.0", rescanned("1.0", Driver.Status.STALE), "done");
        assertEquals(Driver.Status.UPDATE_FAILED, r.status());
        assertEquals("Update reported success but installed version unchanged", r.message());
    }
}
