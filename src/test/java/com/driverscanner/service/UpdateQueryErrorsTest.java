package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UpdateQueryErrorsTest {

    private static Driver driver(String name, String date) {
        Driver d = new Driver();
        d.setDeviceName(name);
        d.setDriverDate(date);
        return d;
    }

    private static WindowsUpdateCatalogService service() {
        return new WindowsUpdateCatalogService(new OemUpdateService());
    }

    @Test
    void queryErrorMarksEveryDriverUnknownNotDateFallback() {
        List<Driver> ds = List.of(driver("A", "20240101000000.000000-000"), driver("B", "20240101000000.000000-000"));

        service().applyBatchOutput(ds, List.of("QUERY_ERROR|Access is denied"));

        for (Driver d : ds) {
            assertEquals(Driver.Status.UNKNOWN, d.getStatus());
            assertEquals("Windows Update query failed: Access is denied", d.getStatusMessage());
        }
    }

    @Test
    void missingDoneMarkerIsUnknown() {
        List<Driver> ds = List.of(driver("A", "20240101000000.000000-000"));

        service().applyBatchOutput(ds, List.of("0|NONE"));

        assertEquals(Driver.Status.UNKNOWN, ds.get(0).getStatus());
        assertTrue(ds.get(0).getStatusMessage().startsWith("Windows Update query failed"));
    }

    @Test
    void completedQueryMapsFoundAndNone() {
        String recent = java.time.LocalDate.now().minusMonths(1).format(java.time.format.DateTimeFormatter.BASIC_ISO_DATE)
            + "000000.000000-000";
        List<Driver> ds = List.of(driver("A", recent), driver("B", recent));

        service().applyBatchOutput(ds, List.of("0|FOUND|A v2|KB123|2025-01-01", "1|NONE", "DONE"));

        assertEquals(Driver.Status.STALE, ds.get(0).getStatus());
        assertEquals("KB123", ds.get(0).getUpdateKbId());
        assertEquals(Driver.Status.UP_TO_DATE, ds.get(1).getStatus());
    }

    @Test
    void moduleErrorFallsBackToDateWithExplanatoryMessage() {
        String recent = java.time.LocalDate.now().minusMonths(1).format(java.time.format.DateTimeFormatter.BASIC_ISO_DATE)
            + "000000.000000-000";
        List<Driver> ds = List.of(driver("A", recent));

        service().applyBatchOutput(ds, List.of("Import-Module : the module could not be loaded"));

        assertEquals(Driver.Status.UP_TO_DATE, ds.get(0).getStatus());
        assertEquals("Windows Update unavailable - date-based estimate", ds.get(0).getStatusMessage());
    }

    @Test
    void chunkingKeepsEachChunkWithinBudgetAndPreservesOrder() {
        List<Driver> ds = new ArrayList<>();
        for (int i = 0; i < 20; i++) ds.add(driver("Device-" + i, null));

        int budget = 60;
        List<List<Driver>> chunks = service().chunkByBudget(ds, budget);

        assertTrue(chunks.size() > 1);
        List<Driver> flat = new ArrayList<>();
        for (List<Driver> c : chunks) {
            int len = c.stream().mapToInt(d -> d.getDeviceName().length() + 3).sum();
            assertTrue(len <= budget, "chunk of " + c.size() + " is " + len);
            flat.addAll(c);
        }
        assertEquals(ds, flat);
    }

    @Test
    void oversizedSingleNameStillGetsItsOwnChunk() {
        List<List<Driver>> chunks = service().chunkByBudget(List.of(driver("x".repeat(100), null), driver("y", null)), 10);

        assertEquals(2, chunks.size());
    }

    static class OemStub extends OemUpdateService {
        final int exit;
        final String output;
        int calls;

        OemStub(int exit, String output) {
            this.exit = exit;
            this.output = output;
        }

        @Override
        ProcessResult run(String... command) {
            calls++;
            return new ProcessResult(exit, output);
        }
    }

    @Test
    void nonZeroExitIsNotCachedAndReturnsUnknown() {
        OemStub oem = new OemStub(1, "Lenovo");

        assertEquals(OemUpdateService.Oem.UNKNOWN, oem.detectOem());
        assertEquals(OemUpdateService.Oem.UNKNOWN, oem.detectOem());
        assertEquals(2, oem.calls, "failed lookups must not be cached");
    }

    @Test
    void multiLineManufacturerOutputIsNotCached() {
        OemStub oem = new OemStub(0, "warning noise\nLenovo");

        assertEquals(OemUpdateService.Oem.UNKNOWN, oem.detectOem());
        assertEquals(OemUpdateService.Oem.UNKNOWN, oem.detectOem());
        assertEquals(2, oem.calls);
    }
}
