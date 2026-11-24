package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;

/**
 * Checks the Windows Update catalog for newer driver versions.
 *
 * One PowerShell run asks the Windows Update Agent (Microsoft.Update.Session COM API) for every
 * applicable, not-installed driver update; installed drivers are then matched to those updates by
 * hardware ID in Java (see {@link CatalogMatcher}).
 */
@Service
public class WindowsUpdateCatalogService {

    private static final Logger log = Logger.getLogger(WindowsUpdateCatalogService.class.getName());
    private static final String QUERY_ERROR_MARKER = "QUERY_ERROR";
    private static final String WUA_UNAVAILABLE_MARKER = "WUA_UNAVAILABLE";
    private static final String DONE_MARKER = "DONE";
    private static final String DATE_ESTIMATE_MESSAGE = "Windows Update unavailable - date-based estimate";
    private static final long KILL_WAIT_SECONDS = 5;
    private static final String UTF8_BOM = "﻿";

    /**
     * Emits one {@code UPD|hwid|date|model|provider|class|kb|updateId|version|title} line per hardware ID
     * an update targets (one per WindowsDriverUpdateEntries entry; the update-level properties when it
     * has none). version is blank unless WUA exposes a driver version. Text fields are stripped of '|'
     * and line breaks; Title goes last so the Java parser is exact even if that fails.
     * No double quotes: they do not survive Windows command-line quoting.
     */
    static final String CATALOG_SCRIPT = """
        try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
        function S($v) { if ($null -eq $v) { '' } else { ([string]$v) -replace '[|\\r\\n\\t]', ' ' } }
        function P($h, $dt, $m, $p, $c, $v) {
            $d = '';
            if ($dt) { $d = ([datetime]$dt).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
            Write-Output ('UPD|' + (S $h) + '|' + $d + '|' + (S $m) + '|' + (S $p) + '|' + (S $c) + '|' + $kb + '|' + $id + '|' + (S $v) + '|' + $t)
        }
        try {
            $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop;
            $searcher = $session.CreateUpdateSearcher();
            <# 2 = ssWindowsUpdate: a WSUS-managed machine would otherwise ask WSUS, which rarely carries drivers #>
            $searcher.ServerSelection = 2;
        } catch {
            Write-Output ('%1$s|' + ($_.Exception.Message -replace '\\s+',' '));
            exit 1
        }
        try {
            $result = $searcher.Search('IsInstalled=0 and Type=''Driver''');
            foreach ($u in $result.Updates) {
                $kb = (@($u.KBArticleIDs) | ForEach-Object { S $_ }) -join ',';
                $id = S $u.Identity.UpdateID;
                $t = S $u.Title;
                $n = 0;
                try {
                    foreach ($e in $u.WindowsDriverUpdateEntries) {
                        if ($e.HardwareID) { P $e.HardwareID $e.DriverVerDate $e.DriverModel $e.DriverProvider $e.DriverClass $e.DriverVerVersion; $n++ }
                    }
                } catch {}
                if ($n -eq 0) { P $u.DriverHardwareID $u.DriverVerDate $u.DriverModel $u.DriverProvider $u.DriverClass $u.DriverVerVersion }
            }
        } catch {
            Write-Output ('%2$s|' + ($_.Exception.Message -replace '\\s+',' '));
            exit 1
        }
        Write-Output '%3$s'
        """.formatted(WUA_UNAVAILABLE_MARKER, QUERY_ERROR_MARKER, DONE_MARKER);

    private final OemUpdateService oemUpdateService;

    @Value("${driver.scan.ps-timeout-seconds:300}")
    private long psTimeoutSeconds = 300;

    public WindowsUpdateCatalogService(OemUpdateService oemUpdateService) {
        this.oemUpdateService = oemUpdateService;
    }

    /** Single-driver variant of {@link #batchCheckForUpdates(List)}. */
    public void checkForUpdates(Driver driver) {
        batchCheckForUpdates(new ArrayList<>(List.of(driver)));
    }

    /**
     * Firmware drivers are routed to OemUpdateService; virtual Windows drivers are skipped.
     * All remaining drivers share one Windows Update Agent query.
     */
    public void batchCheckForUpdates(List<Driver> drivers) {
        List<Driver> firmware = new ArrayList<>();
        List<Driver> toQuery  = new ArrayList<>();

        for (Driver d : drivers) {
            if (isVirtualWindowsDriver(d)) {
                d.setStatus(Driver.Status.UP_TO_DATE);
                d.setStatusMessage("Built-in Windows component - not applicable for updates.");
            } else if ("Firmware".equals(d.getDeviceClass())) {
                firmware.add(d);
            } else {
                toQuery.add(d);
            }
        }

        // OEM tools give one machine-wide verdict: one vendor run for all firmware drivers
        oemUpdateService.checkFirmwareForUpdates(firmware);

        if (!toQuery.isEmpty()) {
            queryWindowsUpdate(toQuery);
        }
    }

    private void queryWindowsUpdate(List<Driver> drivers) {
        try {
            applyBatchOutput(drivers, runBatchScript(CATALOG_SCRIPT));
        } catch (Exception e) {
            log.warning("Windows Update driver query failed: " + e.getMessage());
            markQueryFailed(drivers, String.valueOf(e.getMessage()));
        }
    }

    /** Output goes to a file so a hung process cannot block the reader past the timeout. */
    List<String> runBatchScript(String psCmd) throws Exception {
        Path out = Files.createTempFile("wu-driver-scan", ".txt");
        try {
            Process process = startPowerShell(psCmd, out.toFile());
            if (!process.waitFor(psTimeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                // Let the killed process release the output file before the finally block deletes it.
                process.waitFor(KILL_WAIT_SECONDS, TimeUnit.SECONDS);
                throw new TimeoutException("timed out after " + psTimeoutSeconds + " s");
            }
            List<String> lines = new ArrayList<>();
            String text = new String(Files.readAllBytes(out), StandardCharsets.UTF_8);
            if (text.startsWith(UTF8_BOM)) text = text.substring(1);
            text.lines()
                .filter(l -> !l.isBlank())
                .forEach(l -> lines.add(l.trim()));
            return lines;
        } finally {
            try {
                Files.deleteIfExists(out);
            } catch (Exception e) {
                out.toFile().deleteOnExit();
            }
        }
    }

    Process startPowerShell(String script, File output) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
            "powershell.exe", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script
        );
        pb.redirectErrorStream(true);
        pb.redirectOutput(output);
        return pb.start();
    }

    void setPsTimeoutSeconds(long psTimeoutSeconds) {
        this.psTimeoutSeconds = psTimeoutSeconds;
    }

    private void markQueryFailed(List<Driver> drivers, String reason) {
        for (Driver d : drivers) {
            d.setStatus(Driver.Status.UNKNOWN);
            d.setStatusMessage("Windows Update query failed: " + reason);
        }
    }

    /** Interprets one query run's output; a failed query is UNKNOWN, never silently up to date. */
    void applyBatchOutput(List<Driver> drivers, List<String> lines) {
        // An explicit query failure wins over the text heuristics below: its message may contain them.
        String errPrefix = QUERY_ERROR_MARKER + "|";
        String queryError = lines.stream().filter(l -> l.startsWith(errPrefix)).findFirst()
            .map(l -> l.substring(errPrefix.length())).orElse(null);
        if (queryError != null) {
            log.warning("Windows Update query failed: " + queryError);
            markQueryFailed(drivers, queryError);
            return;
        }

        // Update titles are data, not diagnostics: keep them out of the error-text checks.
        String fullOutput = String.join("\n",
            lines.stream().filter(l -> !l.startsWith(CatalogMatcher.UPDATE_PREFIX + "|")).toList());
        boolean agentUnavailable = lines.stream().anyMatch(l -> l.startsWith(WUA_UNAVAILABLE_MARKER + "|"))
            || fullOutput.contains("AuthorizationManager check failed")
            || fullOutput.contains("CouldNotAutoloadMatchingModule")
            || fullOutput.contains("module could not be loaded")
            || fullOutput.contains("not recognized");

        if (agentUnavailable) {
            String reason = lines.isEmpty() ? "unknown" : lines.get(0);
            log.warning("Windows Update Agent unavailable (" + reason + ") - using date-based estimate");
            for (Driver d : drivers) {
                checkByDriverDate(d);
                if (d.getStatus() != Driver.Status.UNKNOWN)
                    d.setStatusMessage(DATE_ESTIMATE_MESSAGE);
            }
            return;
        }

        if (!lines.contains(DONE_MARKER)) {
            String reason = lines.isEmpty() ? "no output" : "incomplete output: " + lines.get(0);
            log.warning("Windows Update query did not complete: " + reason);
            markQueryFailed(drivers, reason);
            return;
        }

        Map<String, List<CatalogMatcher.CatalogUpdate>> catalog = CatalogMatcher.parse(lines);
        log.info("Windows Update offers " + catalog.values().stream().mapToInt(List::size).sum()
            + " driver update(s) for " + catalog.size() + " hardware ID(s)");
        for (Driver d : drivers) {
            CatalogMatcher.apply(d, CatalogMatcher.findBest(d, catalog));
        }
    }

    /** Fallback only when the Windows Update Agent itself is unavailable: stale if older than 24 months. */
    private void checkByDriverDate(Driver driver) {
        String rawDate = driver.getDriverDate();
        if (rawDate == null || rawDate.isBlank()) {
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Driver date unavailable.");
            return;
        }
        LocalDate driverDate = CatalogMatcher.parseDriverDate(rawDate);
        if (driverDate == null) {
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Could not parse driver date: " + rawDate);
            return;
        }
        if (driverDate.isBefore(LocalDate.now().minusMonths(24))) {
            driver.setStatus(Driver.Status.STALE);
            driver.setStatusMessage("Driver date is over 24 months old.");
        } else {
            driver.setStatus(Driver.Status.UP_TO_DATE);
            driver.setStatusMessage("Driver is recent (date-based check).");
        }
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
}
