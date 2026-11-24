package com.driverscanner.service;

import com.driverscanner.model.Driver;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.logging.Logger;

/**
 * Checks Windows Update catalog for newer driver versions.
 *
 * Strategy:
 * 1. Query Microsoft's public Update Catalog search endpoint
 * 2. Parse results to find matching drivers
 * 3. Compare version strings / dates
 *
 * Note: The Windows Update Catalog does not have an official REST API.
 * We use the PowerShell PSWindowsUpdate module as the reliable fallback,
 * which is the production-grade approach used by enterprise tools.
 */
@Service
public class WindowsUpdateCatalogService {

    private static final Logger log = Logger.getLogger(WindowsUpdateCatalogService.class.getName());
    private final ObjectMapper mapper = new ObjectMapper();
    private static final String QUERY_ERROR_MARKER = "QUERY_ERROR";
    private static final String DONE_MARKER = "DONE";
    private final OemUpdateService oemUpdateService;

    @Value("${driver.scan.ps-command-max-chars:24000}")
    private int psCommandMaxChars = 24000;

    public WindowsUpdateCatalogService(OemUpdateService oemUpdateService) {
        this.oemUpdateService = oemUpdateService;
    }

    /**
     * Checks if a newer driver or firmware update is available.
     * Firmware-class devices are delegated to OemUpdateService (Dell DCU / Lenovo SU / WU firmware).
     * All other devices use PSWindowsUpdate driver category.
     */
    public void checkForUpdates(Driver driver) {
        log.info("[BP1] checkForUpdates: name='" + driver.getDeviceName() + "' class='" + driver.getDeviceClass() + "' date='" + driver.getDriverDate() + "' version='" + driver.getDriverVersion() + "'");
        if (isVirtualWindowsDriver(driver)) {
            log.info("[BP1a] Skipping stale check for virtual Windows driver: " + driver.getDeviceName());
            driver.setStatus(Driver.Status.UP_TO_DATE);
            driver.setStatusMessage("Built-in Windows component - not applicable for updates.");
            return;
        }
        if ("Firmware".equals(driver.getDeviceClass())) {
            log.info("[BP2] Routing to OemUpdateService (Firmware class)");
            oemUpdateService.checkFirmwareForUpdates(driver);
            return;
        }
        try {
            oemUpdateService.ensurePSWindowsUpdate();
            String psCmd = String.format("""
                Import-Module PSWindowsUpdate -ErrorAction Stop;
                $all = Get-WindowsUpdate -Category 'Drivers' -ErrorAction SilentlyContinue;
                $pat = [Regex]::Escape('%s');
                $u = $all | Where-Object { $_.Title -match $pat } | Select-Object -First 1;
                if ($u) {
                    Write-Output ($u.Title + '|' + ($u.KBArticleIDs -join ',') + '|' + $u.LastDeploymentChangeTime)
                } else {
                    Write-Output 'NONE'
                }
                """, escapeForPowerShell(driver.getDeviceName()));

            ProcessBuilder pb = new ProcessBuilder(
                "powershell.exe", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line);
                }
            }
            process.waitFor();

            String result = output.toString().trim();
            log.info("[BP3] PSWindowsUpdate raw result: '" + result + "'");
            boolean moduleLoadError = result.contains("AuthorizationManager check failed")
                || result.contains("CouldNotAutoloadMatchingModule")
                || result.contains("FormatXmlUpdateException")
                || result.contains("module could not be loaded");
            if (moduleLoadError || result.startsWith("ERROR") || result.contains("not recognized")) {
                log.warning("[BP4a] PSWindowsUpdate module error — falling back to date check. Reason: " + result.lines().findFirst().orElse("unknown"));
                checkByDriverDate(driver);
            } else if (result.endsWith("NONE") || result.isEmpty()) {
                log.info("[BP4b] PSWindowsUpdate returned NONE — falling back to date check");
                checkByDriverDate(driver);
            } else {
                log.info("[BP4c] PSWindowsUpdate found update: " + result);
                String[] parts = result.split("\\|", 3);
                driver.setStatus(Driver.Status.STALE);
                driver.setLatestVersion(parts.length > 0 ? parts[0] : "Unknown");
                if (parts.length > 1 && !parts[1].isBlank())
                    driver.setUpdateKbId(parts[1].split(",")[0].trim());
                driver.setStatusMessage("Update available: " + result);
            }

        } catch (Exception e) {
            log.warning("Windows Update catalog check failed for " + driver.getDeviceName() + ": " + e.getMessage());
            // Fallback: mark unknown
            checkByDriverDate(driver);
        }
    }

    /**
     * Fallback: mark driver as stale if its date is older than 24 months.
     * Used when PSWindowsUpdate is unavailable.
     */
    private void checkByDriverDate(Driver driver) {
        String rawDate = driver.getDriverDate();
        log.info("[BP5] checkByDriverDate: rawDate='" + rawDate + "'");
        if (rawDate == null || rawDate.isBlank()) {
            log.warning("[BP5a] Driver date is null/blank — setting UNKNOWN");
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Driver date unavailable.");
            return;
        }

        LocalDate driverDate = parseDriverDate(rawDate);
        log.info("[BP6] parseDriverDate result: " + driverDate);
        if (driverDate == null) {
            log.warning("[BP6a] Could not parse date '" + rawDate + "' — setting UNKNOWN");
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Could not parse driver date: " + rawDate);
            return;
        }

        LocalDate cutoff = LocalDate.now().minusMonths(24);
        log.info("[BP7] driverDate=" + driverDate + " cutoff=" + cutoff + " isBefore=" + driverDate.isBefore(cutoff));
        if (driverDate.isBefore(cutoff)) {
            log.info("[BP7a] → STALE");
            driver.setStatus(Driver.Status.STALE);
            driver.setStatusMessage("Driver date is over 24 months old.");
        } else {
            log.info("[BP7b] → UP_TO_DATE");
            driver.setStatus(Driver.Status.UP_TO_DATE);
            driver.setStatusMessage("Driver is recent (date-based check).");
        }
    }

    private LocalDate parseDriverDate(String raw) {
        // Raw WMI string: 20060621000000.000000-000
        if (raw.length() >= 8 && raw.charAt(4) != '-' && raw.charAt(4) != '/') {
            try {
                LocalDate d = LocalDate.parse(raw.substring(0, 8), DateTimeFormatter.ofPattern("yyyyMMdd"));
                log.info("[BP6-fmt] Parsed as WMI format (yyyyMMdd)");
                return d;
            } catch (Exception ignored) {}
        }
        // ISO format from PowerShell DateTime serialization: 2006-06-21 or 2006-06-21 00:00:00
        if (raw.length() >= 10) {
            try {
                LocalDate d = LocalDate.parse(raw.substring(0, 10), DateTimeFormatter.ofPattern("yyyy-MM-dd"));
                log.info("[BP6-fmt] Parsed as ISO format (yyyy-MM-dd)");
                return d;
            } catch (Exception ignored) {}
        }
        // US locale PowerShell format: 6/21/2006 12:00:00 AM
        try {
            String datePart = raw.trim().split("\\s+")[0];
            LocalDate d = LocalDate.parse(datePart, DateTimeFormatter.ofPattern("M/d/yyyy"));
            log.info("[BP6-fmt] Parsed as US locale format (M/d/yyyy)");
            return d;
        } catch (Exception ignored) {}
        log.warning("[BP6-fmt] All date format attempts failed for: '" + raw + "'");
        return null;
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
        // Escape single quotes for PowerShell string safety
        return input.replace("'", "''").replace("\"", "`\"");
    }

    /**
     * Checks all drivers in a single PowerShell invocation instead of one process per driver.
     * Firmware drivers are routed to OemUpdateService; virtual Windows drivers are skipped.
     * All remaining drivers are checked via a single Get-WindowsUpdate -Category 'Drivers' call
     * whose results are filtered in-memory — eliminating N-1 extra PowerShell startups.
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
            batchQueryPSWindowsUpdate(toQuery);
        }
    }

    private void batchQueryPSWindowsUpdate(List<Driver> drivers) {
        try {
            oemUpdateService.ensurePSWindowsUpdate();
        } catch (Exception e) {
            log.warning("ensurePSWindowsUpdate failed: " + e.getMessage());
        }
        for (List<Driver> chunk : chunkByBudget(drivers, psCommandMaxChars)) {
            try {
                String namesArray = chunk.stream()
                    .map(this::quotedName)
                    .collect(Collectors.joining(","));
                applyBatchOutput(chunk, runBatchScript(buildBatchScript(namesArray)));
            } catch (Exception e) {
                log.warning("Batch PSWindowsUpdate query failed: " + e.getMessage());
                markQueryFailed(chunk, String.valueOf(e.getMessage()));
            }
        }
    }

    private String quotedName(Driver d) {
        return "'" + escapeForPowerShell(d.getDeviceName()) + "'";
    }

    private static String buildBatchScript(String namesArray) {
        return String.format("""
            Import-Module PSWindowsUpdate;
            try {
                $all = Get-WindowsUpdate -Category 'Drivers' -ErrorAction Stop;
            } catch {
                Write-Output ('%s|' + ($_.Exception.Message -replace '\\s+',' '));
                exit 1
            }
            $names = @(%s);
            for ($i = 0; $i -lt $names.Count; $i++) {
                $name = $names[$i];
                $pat = [Regex]::Escape($name);
                $m = $all | Where-Object { $_.Title -match $pat } | Select-Object -First 1;
                if ($m) {
                    Write-Output ("$i|FOUND|" + $m.Title + "|" + ($m.KBArticleIDs -join ',') + "|" + $m.LastDeploymentChangeTime)
                } else {
                    Write-Output "$i|NONE"
                }
            }
            Write-Output '%s'
            """, QUERY_ERROR_MARKER, namesArray, DONE_MARKER);
    }

    List<String> runBatchScript(String psCmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
            "powershell.exe", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd
        );
        pb.redirectErrorStream(true);
        Process process = pb.start();
        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isBlank()) lines.add(line.trim());
            }
        }
        process.waitFor();
        return lines;
    }

    /** Splits so each chunk's joined names array stays within the budget; an oversized name gets its own chunk. */
    List<List<Driver>> chunkByBudget(List<Driver> drivers, int budget) {
        List<List<Driver>> chunks = new ArrayList<>();
        List<Driver> current = new ArrayList<>();
        int used = 0;
        for (Driver d : drivers) {
            int len = quotedName(d).length() + 1;
            if (!current.isEmpty() && used + len > budget) {
                chunks.add(current);
                current = new ArrayList<>();
                used = 0;
            }
            current.add(d);
            used += len;
        }
        if (!current.isEmpty()) chunks.add(current);
        return chunks;
    }

    void setPsTimeoutSeconds(long s) {}

    Process startPowerShell(String script, java.io.File output) throws Exception { throw new UnsupportedOperationException(); }

    void setPsCommandMaxChars(int psCommandMaxChars) {
        this.psCommandMaxChars = psCommandMaxChars;
    }

    private void markQueryFailed(List<Driver> drivers, String reason) {
        for (Driver d : drivers) {
            d.setStatus(Driver.Status.UNKNOWN);
            d.setStatusMessage("Windows Update query failed: " + reason);
        }
    }

    /** Interprets one batch run's output; a failed query is UNKNOWN, never silently up to date. */
    void applyBatchOutput(List<Driver> drivers, List<String> lines) {
        String fullOutput = String.join("\n", lines);
        boolean moduleError = fullOutput.contains("AuthorizationManager check failed")
            || fullOutput.contains("CouldNotAutoloadMatchingModule")
            || fullOutput.contains("module could not be loaded")
            || fullOutput.contains("not recognized");

        if (moduleError) {
            String reason = lines.isEmpty() ? "unknown" : lines.get(0);
            log.warning("PSWindowsUpdate module unavailable (" + reason + ") - using date-based estimate");
            for (Driver d : drivers) {
                checkByDriverDate(d);
                if (d.getStatus() != Driver.Status.UNKNOWN)
                    d.setStatusMessage("Windows Update unavailable - date-based estimate");
            }
            return;
        }

        String errPrefix = QUERY_ERROR_MARKER + "|";
        String queryError = lines.stream().filter(l -> l.startsWith(errPrefix)).findFirst()
            .map(l -> l.substring(errPrefix.length())).orElse(null);
        if (queryError != null) {
            log.warning("Windows Update query failed: " + queryError);
            markQueryFailed(drivers, queryError);
            return;
        }
        if (!lines.contains(DONE_MARKER)) {
            String reason = lines.isEmpty() ? "no output" : "incomplete output: " + lines.get(0);
            log.warning("Windows Update query did not complete: " + reason);
            markQueryFailed(drivers, reason);
            return;
        }

        boolean[] matched = new boolean[drivers.size()];
        for (String line : lines) {
            String[] parts = line.split("\\|", 5);
            if (parts.length < 2) continue;
            try {
                int idx = Integer.parseInt(parts[0]);
                if (idx < 0 || idx >= drivers.size()) continue;
                matched[idx] = true;
                Driver d = drivers.get(idx);
                if ("FOUND".equals(parts[1])) {
                    d.setStatus(Driver.Status.STALE);
                    d.setLatestVersion(parts.length > 2 ? parts[2] : "Unknown");
                    if (parts.length > 3 && !parts[3].isBlank())
                        d.setUpdateKbId(parts[3].split(",")[0].trim());
                    d.setStatusMessage("Update available: " + (parts.length > 2 ? parts[2] : line));
                } else {
                    checkByDriverDate(d);
                }
            } catch (NumberFormatException ignored) {}
        }
        for (int i = 0; i < drivers.size(); i++) {
            if (!matched[i]) {
                drivers.get(i).setStatus(Driver.Status.UNKNOWN);
                drivers.get(i).setStatusMessage("Windows Update query failed: no result for device");
            }
        }
    }
}
