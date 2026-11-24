package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class FirmwareCheckOnceTest {

    /** Simulates a Lenovo machine with Thin Installer present; records every process launch. */
    static class FakeLenovoOem extends OemUpdateService {
        final List<List<String>> commands = new CopyOnWriteArrayList<>();

        @Override
        boolean fileExists(String path) {
            return path.endsWith("ThinInstaller.exe");
        }

        @Override
        ProcessResult run(String... command) {
            commands.add(List.of(command));
            if (command[0].equalsIgnoreCase("powershell.exe")) {
                return new ProcessResult(0, "LENOVO");
            }
            return new ProcessResult(0, "");
        }

        List<List<String>> vendorCalls() {
            return commands.stream().filter(c -> c.get(0).endsWith("ThinInstaller.exe")).toList();
        }

        long wmiCalls() {
            return commands.stream().filter(c -> c.get(0).equalsIgnoreCase("powershell.exe")).count();
        }
    }

    private static Driver firmware(int i) {
        Driver d = new Driver();
        d.setDeviceId("fw-" + i);
        d.setDeviceName("System Firmware " + i);
        d.setDeviceClass("Firmware");
        return d;
    }

    @Test
    void vendorToolRunsOnceForAllFirmwareDriversAndIsReadOnly() {
        FakeLenovoOem oem = new FakeLenovoOem();
        WindowsUpdateCatalogService catalog = new WindowsUpdateCatalogService(oem);
        List<Driver> drivers = IntStream.range(0, 5).mapToObj(FirmwareCheckOnceTest::firmware).toList();

        catalog.batchCheckForUpdates(drivers);

        List<List<String>> vendor = oem.vendorCalls();
        assertEquals(1, vendor.size(), "vendor tool must be invoked exactly once per scan");
        assertTrue(vendor.get(0).contains("LIST"), "check must use -action LIST");
        assertFalse(vendor.get(0).contains("INSTALL"), "check must never install");
        assertEquals(1, oem.wmiCalls(), "OEM detection must query WMI once");
        for (Driver d : drivers) {
            assertEquals(Driver.Status.UP_TO_DATE, d.getStatus());
            assertEquals(drivers.get(0).getStatusMessage(), d.getStatusMessage());
        }
    }
}
