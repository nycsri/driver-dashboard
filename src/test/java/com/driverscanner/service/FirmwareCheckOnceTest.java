package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class FirmwareCheckOnceTest {

    /** Records every process launch; WMI answers come from a queue (last one repeats). */
    static class FakeOem extends OemUpdateService {
        final List<List<String>> commands = new CopyOnWriteArrayList<>();
        final Deque<String> manufacturers = new ArrayDeque<>();
        final String presentTool;
        int vendorExit;
        String vendorOutput;
        String firmwareQueryOutput = "";

        FakeOem(String presentTool, int vendorExit, String vendorOutput, String... manufacturers) {
            this.presentTool = presentTool;
            this.vendorExit = vendorExit;
            this.vendorOutput = vendorOutput;
            this.manufacturers.addAll(List.of(manufacturers));
        }

        @Override
        boolean fileExists(String path) {
            return presentTool != null && path.endsWith(presentTool);
        }

        @Override
        ProcessResult run(String... command) throws Exception {
            commands.add(List.of(command));
            if (command[0].equalsIgnoreCase("powershell.exe")) {
                String script = command[command.length - 1];
                if (script.contains("Win32_ComputerSystem")) {
                    String m = manufacturers.size() > 1 ? manufacturers.poll() : manufacturers.peek();
                    if ("THROW".equals(m)) throw new IllegalStateException("WMI unavailable");
                    return new ProcessResult(0, m);
                }
                if (script.contains("Get-WindowsUpdate")) return new ProcessResult(0, firmwareQueryOutput);
                return new ProcessResult(0, "");
            }
            return new ProcessResult(vendorExit, vendorOutput);
        }

        List<List<String>> vendorCalls() {
            return commands.stream().filter(c -> !c.get(0).equalsIgnoreCase("powershell.exe")).toList();
        }

        long psCallsContaining(String fragment) {
            return commands.stream()
                .filter(c -> c.get(0).equalsIgnoreCase("powershell.exe"))
                .filter(c -> c.get(c.size() - 1).contains(fragment))
                .count();
        }
    }

    private static FakeOem lenovo(int exit, String output) {
        return new FakeOem("ThinInstaller.exe", exit, output, "LENOVO");
    }

    private static Driver firmware(int i) {
        Driver d = new Driver();
        d.setDeviceId("fw-" + i);
        d.setDeviceName("System Firmware " + i);
        d.setDeviceClass("Firmware");
        return d;
    }

    private static List<Driver> firmwareDrivers(int n) {
        return IntStream.range(0, n).mapToObj(FirmwareCheckOnceTest::firmware).toList();
    }

    @Test
    void vendorToolRunsOnceForAllFirmwareDriversAndIsReadOnly() {
        FakeOem oem = lenovo(10000, "");
        List<Driver> drivers = firmwareDrivers(5);

        new WindowsUpdateCatalogService(oem).batchCheckForUpdates(drivers);

        List<List<String>> vendor = oem.vendorCalls();
        assertEquals(1, vendor.size(), "vendor tool must be invoked exactly once per scan");
        assertTrue(vendor.get(0).contains("SCAN"), "check must use -action SCAN");
        assertFalse(vendor.get(0).contains("INSTALL"), "check must never install");
        assertEquals(1, oem.psCallsContaining("Win32_ComputerSystem"), "OEM detection must query WMI once");
        for (Driver d : drivers) {
            assertEquals(Driver.Status.UP_TO_DATE, d.getStatus());
            assertEquals(drivers.get(0).getStatusMessage(), d.getStatusMessage());
        }
    }

    @Test
    void blankLenovoOutputIsUnknownNotUpToDate() throws Exception {
        OemUpdateService.FirmwareCheck check = lenovo(0, "").checkFirmwareOnce();

        assertEquals(Driver.Status.UNKNOWN, check.status());
        assertTrue(check.message().contains("could not be determined"), check.message());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "10001 | ''                              | STALE",
        "10000 | ''                              | UP_TO_DATE",
        "0     | 10 packages found               | STALE",
        "0     | Found 3 packages                | STALE",
        "0     | 1 package found                 | STALE",
        "0     | 0 packages found                | UP_TO_DATE",
        "0     | No applicable updates were found | UP_TO_DATE",
        "0     | Scanning repository...          | UNKNOWN",
        "1     | 0 packages found                | UNKNOWN",
    })
    void lenovoVerdict(int exit, String output, Driver.Status expected) throws Exception {
        assertEquals(expected, lenovo(exit, output).checkFirmwareOnce().status(), output);
    }

    @Test
    void systemUpdateKernelIsNotUsedForChecks() throws Exception {
        FakeOem oem = new FakeOem("tvsukernel.exe", 0, "", "LENOVO");

        assertNull(oem.checkFirmwareOnce(), "undocumented tvsukernel.exe must not be used for read-only checks");
        assertTrue(oem.vendorCalls().isEmpty());
    }

    @ParameterizedTest
    @CsvSource({
        "500, UP_TO_DATE",
        "0,   STALE",
        "5,   UNKNOWN",
        "501, UNKNOWN",
    })
    void dellScanExitCodes(int exit, Driver.Status expected) throws Exception {
        FakeOem oem = new FakeOem("dcu-cli.exe", exit, "", "Dell Inc.");
        assertEquals(expected, oem.checkFirmwareOnce().status());
    }

    @Test
    void failedWmiLookupIsRetriedOnNextCall() {
        FakeOem oem = new FakeOem(null, 0, "", "THROW", "", "LENOVO");

        assertEquals(OemUpdateService.Oem.UNKNOWN, oem.detectOem());
        assertEquals(OemUpdateService.Oem.UNKNOWN, oem.detectOem());
        assertEquals(OemUpdateService.Oem.LENOVO, oem.detectOem());
        assertEquals(OemUpdateService.Oem.LENOVO, oem.detectOem());
        assertEquals(3, oem.psCallsContaining("Win32_ComputerSystem"), "only the successful lookup is cached");
    }

    @Test
    void windowsUpdateFallbackQueriesOnceAndMatchesInMemory() {
        FakeOem oem = new FakeOem(null, 0, "", "Contoso Ltd");
        oem.firmwareQueryOutput = "TITLE:Contoso - Firmware - System Firmware 3 v2.1\nDONE";
        List<Driver> drivers = firmwareDrivers(5);

        oem.checkFirmwareForUpdates(drivers);

        assertEquals(1, oem.psCallsContaining("Get-WindowsUpdate -Category 'Firmware'"));
        for (Driver d : drivers) {
            Driver.Status expected = d.getDeviceName().equals("System Firmware 3")
                ? Driver.Status.STALE : Driver.Status.UP_TO_DATE;
            assertEquals(expected, d.getStatus(), d.getDeviceName());
        }
    }

    @Test
    void windowsUpdateFallbackWithoutCompletionMarkerIsUnknown() {
        FakeOem oem = new FakeOem(null, 0, "", "Contoso Ltd");
        oem.firmwareQueryOutput = "Import-Module : module not found";
        Driver d = firmware(1);

        oem.checkFirmwareForUpdates(d);

        assertEquals(Driver.Status.UNKNOWN, d.getStatus());
    }
}
