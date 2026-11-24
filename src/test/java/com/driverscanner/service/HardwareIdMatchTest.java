package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class HardwareIdMatchTest {

    private static final String GUID = "0a1b2c3d-4e5f-6789-abcd-ef0123456789";
    private static final String HWID = "PCI\\VEN_8086&DEV_A0F0&SUBSYS_00748086";

    private static Driver driver(String name, String version, String date, String... hwids) {
        Driver d = new Driver("id-" + name, name, version, date, "P", "Net");
        d.setHardwareIds(List.of(hwids));
        return d;
    }

    private static String upd(String hwid, String date, String kb, String id, String title) {
        return upd(hwid, date, "Net", kb, id, "", title);
    }

    /** UPD|hwid|date|model|provider|class|kb|updateId|version|title */
    private static String upd(String hwid, String date, String cls, String kb, String id, String version, String title) {
        return "UPD|" + hwid + "|" + date + "|Model|Intel|" + cls + "|" + kb + "|" + id + "|" + version + "|" + title;
    }

    private static WindowsUpdateCatalogService service() {
        return new WindowsUpdateCatalogService(new OemUpdateService());
    }

    // --- VersionComparator -------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "22.110.1.1,               22.100.1.1, 1",
        "22.100.1.1,               22.110.1.1, -1",
        "1.2,                      1.2.0.0,    0",
        "1.10,                     1.9,        1",
        "01.002,                   1.2,        0",
        "10.0.99999999999999999999, 10.0.1,    1",
        "1.2.4beta,                1.2.3,      1",
        "1.2.3a,                   1.2.3,      0",
        "abc,                      1.0,        NC",
        "'',                       1.0,        NC",
        "1..2,                     1.0.2,      NC",
    })
    void versionComparatorTable(String a, String b, String expected) {
        OptionalInt r = VersionComparator.compare(a, b);
        if ("NC".equals(expected)) {
            assertTrue(r.isEmpty(), a + " vs " + b);
        } else {
            assertTrue(r.isPresent(), a + " vs " + b);
            assertEquals(Integer.parseInt(expected), Integer.signum(r.getAsInt()), a + " vs " + b);
        }
    }

    @Test
    void versionComparatorRejectsNull() {
        assertTrue(VersionComparator.compare(null, "1.0").isEmpty());
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
        "Intel - Net - 22.110.1.1;                              22.110.1.1",
        "Realtek Semiconductor Corp. - Extension - 10.0.22621.31291; 10.0.22621.31291",
        "Foo 2.1.0 - Bar - 3.4.5;                               3.4.5",
        "Some Driver Update;                                    ''",
        "Weird 1.2.3.4.5;                                       ''",
    })
    void extractsLastDottedVersionFromTitle(String title, String expected) {
        String v = VersionComparator.extractVersion(title);
        assertEquals(expected.isEmpty() ? null : expected, v);
    }

    // --- Parser --------------------------------------------------------------

    @Test
    void parserKeysByUpperCaseHardwareIdAndKeepsPipeInTitle() {
        Map<String, List<CatalogMatcher.CatalogUpdate>> m = CatalogMatcher.parse(List.of(
            upd("pci\\ven_8086&dev_a0f0", "2024-05-01", "123,456", GUID, "Intel - Net | Wi-Fi - 22.110.1.1"),
            "UPD|too|few",
            "garbage line",
            "DONE"));

        assertEquals(1, m.size());
        CatalogMatcher.CatalogUpdate u = m.get("PCI\\VEN_8086&DEV_A0F0").get(0);
        assertEquals("Intel - Net | Wi-Fi - 22.110.1.1", u.title());
        assertEquals(GUID, u.updateId());
        assertEquals("123,456", u.kb());
        assertEquals(java.time.LocalDate.of(2024, 5, 1), u.verDate());
    }

    // --- Matching + decisions -------------------------------------------------

    @Test
    void newerVersionByHardwareIdIsStaleCaseInsensitiveMultiId() {
        Driver d = driver("Intel(R) Wi-Fi 6 AX201", "22.100.1.1", "2023-01-01",
            HWID, "PCI\\VEN_8086&DEV_A0F0");

        service().applyBatchOutput(List.of(d), List.of(
            upd("pci\\ven_8086&dev_a0f0", "2024-01-01", "", "11111111-1111-1111-1111-111111111111", "Intel - Net - 22.105.0.1"),
            upd("PCI\\VEN_8086&DEV_A0F0", "2024-06-01", "5005565", GUID, "Intel - Net - 22.110.1.1"),
            upd("PCI\\VEN_10EC&DEV_8168", "2025-01-01", "", GUID, "Realtek - Net - 99.0.0.0"),
            "DONE"));

        assertEquals(Driver.Status.STALE, d.getStatus());
        assertEquals("22.110.1.1", d.getLatestVersion());
        assertEquals("5005565", d.getUpdateKbId());
        assertEquals(GUID, d.getUpdateId());
    }

    @Test
    void sameVersionIsCurrent() {
        Driver d = driver("Dev", "22.110.1.1", "2024-06-01", HWID);

        service().applyBatchOutput(List.of(d), List.of(upd(HWID, "2024-06-01", "", GUID, "Intel - Net - 22.110.1.1"), "DONE"));

        assertEquals(Driver.Status.UP_TO_DATE, d.getStatus());
        assertEquals("Driver is current (matches Windows Update catalog)", d.getStatusMessage());
        assertNull(d.getUpdateId());
    }

    @Test
    void noVersionInTitleFallsBackToDriverVerDate() {
        Driver older = driver("A", "1.0", "6/21/2023 12:00:00 AM", HWID);
        Driver same = driver("B", "1.0", "2024-06-01", HWID);

        service().applyBatchOutput(List.of(older, same),
            List.of(upd(HWID, "2024-06-01", "", GUID, "Intel - Net"), "DONE"));

        assertEquals(Driver.Status.STALE, older.getStatus());
        assertEquals("2024-06-01", older.getLatestVersion());
        assertEquals(Driver.Status.UP_TO_DATE, same.getStatus());
    }

    @Test
    void noCandidateIsCurrentEvenForVeryOldDriver() {
        Driver d = driver("Old", "1.0", "20100101000000.000000-000", HWID);

        service().applyBatchOutput(List.of(d), List.of(upd("USB\\VID_0000", "2024-06-01", "", GUID, "x - 9.9.9"), "DONE"));

        assertEquals(Driver.Status.UP_TO_DATE, d.getStatus());
        assertEquals("No newer driver in Windows Update catalog", d.getStatusMessage());
    }

    @Test
    void compatibleIdOnlyMatchIsUnknownAndNotInstallable() {
        Driver d = driver("Dev", "1.0.0", "2020-01-01", HWID);
        d.setCompatibleIds(List.of("PCI\\VEN_8086&DEV_A0F0&CC_0280"));

        service().applyBatchOutput(List.of(d), List.of(
            upd("pci\\ven_8086&dev_a0f0&cc_0280", "2024-06-01", "5005565", GUID, "Generic - 2.0.0"), "DONE"));

        assertEquals(Driver.Status.UNKNOWN, d.getStatus());
        assertTrue(d.getStatusMessage().contains("matched by compatible ID only - cannot confirm"), d.getStatusMessage());
        assertNull(d.getUpdateId());
        assertNull(d.getUpdateKbId());
    }

    @Test
    void classCodeIdsAreIgnoredForMatching() {
        Driver d = driver("Dev", "1.0.0", "2020-01-01", HWID, "PCI\\CC_0280");
        d.setCompatibleIds(List.of("USB\\Class_E0&SubClass_01", "PCI\\CC_0280"));

        service().applyBatchOutput(List.of(d), List.of(
            upd("PCI\\CC_0280", "2024-06-01", "", GUID, "Generic - 2.0.0"),
            upd("USB\\CLASS_E0&SUBCLASS_01", "2024-06-01", "", GUID, "Generic - 2.0.0"),
            "DONE"));

        assertEquals(Driver.Status.UP_TO_DATE, d.getStatus());
        assertEquals("No newer driver in Windows Update catalog", d.getStatusMessage());
    }

    @Test
    void anyNewerCandidateIsStaleAndNewestQualifyingIsPicked() {
        Driver d = driver("Dev", "22.100.0.0", "2023-01-01", HWID);
        String id1 = "11111111-1111-1111-1111-111111111111";
        String id3 = "33333333-3333-3333-3333-333333333333";

        service().applyBatchOutput(List.of(d), List.of(
            upd(HWID, "2025-06-01", "", id1, "Intel - Net - 22.050.0.0"),
            upd(HWID, "2024-01-01", "5005565", GUID, "Intel - Net - 22.110.1.1"),
            upd(HWID, "2023-06-01", "", id3, "Intel - Net - 22.105.0.0"),
            "DONE"));

        assertEquals(Driver.Status.STALE, d.getStatus());
        assertEquals("22.110.1.1", d.getLatestVersion());
        assertEquals("5005565", d.getUpdateKbId());
        assertEquals(GUID, d.getUpdateId());
    }

    @Test
    void extensionAndSoftwareComponentSkippedUnlessDeviceClassMatches() {
        Driver net = driver("Net", "1.0.0", "2020-01-01", HWID);
        net.setDeviceClass("Net");
        Driver ext = driver("Ext", "1.0.0", "2020-01-01", HWID);
        ext.setDeviceClass("Extension");

        service().applyBatchOutput(List.of(net, ext), List.of(
            upd(HWID, "2024-06-01", "Extension", "", GUID, "", "Vendor - Extension - 2.0.0"),
            upd(HWID, "2024-06-01", "SoftwareComponent", "", GUID, "", "Vendor - SoftwareComponent - 3.0.0"),
            "DONE"));

        assertEquals(Driver.Status.UP_TO_DATE, net.getStatus());
        assertEquals("No newer driver in Windows Update catalog", net.getStatusMessage());
        assertEquals(Driver.Status.STALE, ext.getStatus());
        assertEquals("2.0.0", ext.getLatestVersion());
    }

    @Test
    void multiEntryUpdateMatchesEveryHardwareIdAndPrefersEntryVersion() {
        String other = "PCI\\VEN_8086&DEV_51F1";
        Driver a = driver("A", "22.100.0.0", "2023-01-01", HWID);
        Driver b = driver("B", "22.100.0.0", "2023-01-01", other);

        service().applyBatchOutput(List.of(a, b), List.of(
            upd(HWID, "2024-06-01", "Net", "5005565", GUID, "22.120.0.0", "Intel - Net - 22.110.1.1"),
            upd(other, "2024-06-01", "Net", "5005565", GUID, "22.120.0.0", "Intel - Net - 22.110.1.1"),
            "DONE"));

        for (Driver d : List.of(a, b)) {
            assertEquals(Driver.Status.STALE, d.getStatus());
            assertEquals("22.120.0.0", d.getLatestVersion());
            assertEquals(GUID, d.getUpdateId());
        }
    }

    @Test
    void catalogScriptIteratesEntriesTargetsWindowsUpdateAndIsUtf8() {
        String s = WindowsUpdateCatalogService.CATALOG_SCRIPT;
        assertTrue(s.contains("$u.WindowsDriverUpdateEntries"), s);
        assertTrue(s.contains("$searcher.ServerSelection = 2"), s);
        assertTrue(s.contains("[Console]::OutputEncoding = [Text.Encoding]::UTF8"), s);
        assertFalse(s.contains("\""), "no double quotes in PowerShell script");
    }

    @Test
    void scannerScriptEmitsInvariantUtcDriverDate() {
        String s = DriverScannerService.PS_QUERY;
        assertTrue(s.contains("ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)"), s);
        assertFalse(s.contains("\""), "no double quotes in PowerShell script");
    }

    @ParameterizedTest
    @CsvSource(delimiter = ';', value = {
        "2023-01-05;                  2023-01-05",
        "20230105000000.000000-000;   2023-01-05",
        "1/5/2023 12:00:00 AM;        2023-01-05",
    })
    void driverDateParsesInvariantAndLegacyFormats(String raw, String expected) {
        assertEquals(java.time.LocalDate.parse(expected), CatalogMatcher.parseDriverDate(raw));
    }

    @Test
    void utf8OutputWithBomIsReadAsUtf8() throws Exception {
        String line = "UPD|" + HWID + "|2024-06-01|M|Realtek®|Net||" + GUID + "||Realtek® – Net – 2.0.0";
        WindowsUpdateCatalogService svc = new WindowsUpdateCatalogService(new OemUpdateService()) {
            @Override
            Process startPowerShell(String script, File output) throws Exception {
                byte[] body = (line + "\r\nDONE\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
                java.nio.file.Files.write(output.toPath(), bom);
                java.nio.file.Files.write(output.toPath(), body, java.nio.file.StandardOpenOption.APPEND);
                return new FakeProcess(true);
            }
        };

        assertEquals(List.of(line, "DONE"), svc.runBatchScript("x"));
    }

    @Test
    void comUnavailableUsesDateEstimateWithDistinctMessage() {
        String recent = java.time.LocalDate.now().minusMonths(1)
            .format(java.time.format.DateTimeFormatter.BASIC_ISO_DATE) + "000000.000000-000";
        Driver d = driver("Dev", "1.0", recent, HWID);

        service().applyBatchOutput(List.of(d), List.of("WUA_UNAVAILABLE|Retrieving the COM class factory failed"));

        assertEquals(Driver.Status.UP_TO_DATE, d.getStatus());
        assertEquals("Windows Update unavailable - date-based estimate", d.getStatusMessage());
    }

    @Test
    void nullNameAndNullIdsDoNotBreakTheBatch() {
        Driver nameless = new Driver();
        nameless.setDriverVersion("1.0");
        Driver d = driver("Dev", "1.0", "2020-01-01", HWID);
        List<Driver> ds = new ArrayList<>(List.of(nameless, d));

        assertDoesNotThrow(() -> service().applyBatchOutput(ds, List.of(upd(HWID, "2024-06-01", "", GUID, "x - 2.0"), "DONE")));

        assertEquals(Driver.Status.STALE, d.getStatus());
        assertNotNull(nameless.getStatus());
    }

    @Test
    void processTimeoutIsUnknownAndKillsProcess() {
        FakeProcess proc = new FakeProcess();
        WindowsUpdateCatalogService svc = new WindowsUpdateCatalogService(new OemUpdateService()) {
            @Override
            Process startPowerShell(String script, File output) {
                return proc;
            }
        };
        svc.setPsTimeoutSeconds(1);
        Driver d = driver("Dev", "1.0", "2020-01-01", HWID);
        d.setDeviceClass("Net");

        svc.batchCheckForUpdates(new ArrayList<>(List.of(d)));

        assertTrue(proc.destroyed);
        assertTrue(proc.waitedAfterDestroy, "temp file must not be deleted before the killed process exits");
        assertEquals(Driver.Status.UNKNOWN, d.getStatus());
        assertTrue(d.getStatusMessage().contains("timed out"), d.getStatusMessage());
    }

    static class FakeProcess extends Process {
        final boolean finishes;
        boolean destroyed;
        boolean waitedAfterDestroy;
        FakeProcess() { this(false); }
        FakeProcess(boolean finishes) { this.finishes = finishes; }
        @Override public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
        @Override public InputStream getInputStream() { return InputStream.nullInputStream(); }
        @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
        @Override public int waitFor() { return 0; }
        @Override public boolean waitFor(long t, TimeUnit u) {
            if (destroyed) waitedAfterDestroy = true;
            return finishes;
        }
        @Override public int exitValue() { throw new IllegalThreadStateException(); }
        @Override public void destroy() { destroyed = true; }
        @Override public Process destroyForcibly() { destroyed = true; return this; }
    }

    // --- Installer lookup (injection boundary) ------------------------------------

    @ParameterizedTest
    @CsvSource(delimiter = '|', quoteCharacter = '"', value = {
        "0a1b2c3d-4e5f-6789-abcd-ef0123456789 | true",
        "0A1B2C3D-4E5F-6789-ABCD-EF0123456789 | true",
        "x'; Remove-Item C:\\ -Recurse; '     | false",
        "0a1b2c3d-4e5f-6789-abcd-ef0123456789' | false",
        "{0a1b2c3d-4e5f-6789-abcd-ef0123456789} | false",
        "\"\"                                  | false",
    })
    void updateIdValidation(String id, boolean valid) {
        assertEquals(valid, WindowsUpdateLookup.isValidUpdateId(id));
    }

    @Test
    void updateIdWithTrailingNewlineOrNullIsRejected() {
        assertFalse(WindowsUpdateLookup.isValidUpdateId(GUID + "\n"));
        assertFalse(WindowsUpdateLookup.isValidUpdateId(null));
    }

    @Test
    void installScriptPrefersValidUpdateId() {
        Driver d = driver("Dev", "1.0", "2020-01-01", HWID);
        d.setUpdateId(GUID);
        d.setUpdateKbId("5005565");

        String ps = WindowsUpdateLookup.buildInstallScript(d);

        assertTrue(ps.contains("Get-WindowsUpdate -UpdateID '" + GUID + "'"), ps);
        assertFalse(ps.contains("-KBArticleID"), ps);
    }

    @Test
    void injectedUpdateIdAndKbAreNeverPutOnTheCommandLine() {
        Driver d = driver("Dev's \"Card\"", "1.0", "2020-01-01", HWID);
        d.setUpdateId("x'; Remove-Item C:\\ -Recurse; '");
        d.setUpdateKbId("1'; Remove-Item C:\\; '");

        String ps = WindowsUpdateLookup.buildInstallScript(d);

        assertFalse(ps.contains("Remove-Item"), ps);
        assertFalse(ps.contains("-UpdateID"), ps);
        assertTrue(ps.contains("[Regex]::Escape('Dev''s \"Card\"')"), ps);
    }

    @Test
    void escapeOnlyDoublesSingleQuotesIncludingCurly() {
        assertEquals("a''b\"c", WindowsUpdateLookup.escapeForPowerShell("a'b\"c"));
        assertEquals("a\u2019\u2019b", WindowsUpdateLookup.escapeForPowerShell("a\u2019b"));
        assertEquals("", WindowsUpdateLookup.escapeForPowerShell(null));
    }

    // --- Scanner CSV ---------------------------------------------------------------

    @Test
    void scannerParsesHardwareIdsAndToleratesOldSixColumnLines() {
        Driver d = DriverScannerService.parseCsvLine(
            "\"Intel(R) Wi-Fi 6 AX201\",\"22.100.1.1\",\"1/1/2023 12:00:00 AM\",\"Intel\",\"NET\",\"PCI\\VEN_8086\\3&11583659&0&A3\","
                + "\"pci\\ven_8086&dev_a0f0&subsys_00748086;PCI\\VEN_8086&DEV_A0F0;pci\\ven_8086&dev_a0f0\",\"PCI\\CC_0280\"");
        assertNotNull(d);
        assertEquals(List.of("PCI\\VEN_8086&DEV_A0F0&SUBSYS_00748086", "PCI\\VEN_8086&DEV_A0F0"), d.getHardwareIds());
        assertEquals(List.of("PCI\\CC_0280"), d.getCompatibleIds());

        Driver old = DriverScannerService.parseCsvLine("\"Dev\",\"1.0\",\"\",\"M\",\"C\",\"ID\"");
        assertNotNull(old);
        assertTrue(old.getHardwareIds().isEmpty());
        assertTrue(old.getCompatibleIds().isEmpty());
    }
}
