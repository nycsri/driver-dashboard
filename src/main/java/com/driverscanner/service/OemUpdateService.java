package com.driverscanner.service;

import com.driverscanner.model.Driver;
import com.driverscanner.model.UpdateResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * Handles firmware staleness checks and updates via OEM-specific CLI tools.
 *
 * OEM detection uses Win32_ComputerSystem.Manufacturer via WMI (cached after first call).
 * Tool paths and exit-code semantics per OEM:
 *
 *   Dell  — Dell Command Update (dcu-cli.exe)
 *             scan exit 0 = updates found, 500 = none, 5 = reboot pending (verdict unknown)
 *             apply exit 0 = success, 1 = reboot needed (treated as success)
 *
 *   Lenovo — Lenovo Thin Installer (ThinInstaller.exe)
 *             scan exit 10001 = updates found, 10000 = none
 *             install exit 3010 = success + reboot needed, 0 = success, non-zero = fail
 *
 *   HP     — HP Image Assistant (HPImageAssistant.exe)
 *             scan exit 0 = no recommendations, 1 = updates available, other = error
 *             install exit 0 = success, 1 = success + reboot needed, other = failure
 *
 *   Unknown — PSWindowsUpdate -Category 'Firmware'
 */
@Service
public class OemUpdateService {

    private static final Logger log = LoggerFactory.getLogger(OemUpdateService.class);

    public enum Oem { DELL, HP, LENOVO, UNKNOWN }

    private static final String DELL_DCU =
        "C:\\Program Files\\Dell\\CommandUpdate\\dcu-cli.exe";
    private static final String LENOVO_THIN_INSTALLER =
        "C:\\Program Files (x86)\\Lenovo\\ThinInstaller\\ThinInstaller.exe";
    private static final String LENOVO_SYSTEM_UPDATE =
        "C:\\Program Files (x86)\\Lenovo\\System Update\\tvsukernel.exe";
    private static final String HP_IMAGE_ASSISTANT =
        "C:\\Program Files\\HP\\HP Image Assistant\\HPImageAssistant.exe";
    private static final String HP_IMAGE_ASSISTANT_X86 =
        "C:\\Program Files (x86)\\HP\\HP Image Assistant\\HPImageAssistant.exe";

    // Vendor CLI protocol values (not tunables): Dell Command | Update and Lenovo CDRT reference guides.
    private static final int DCU_SCAN_UPDATES_FOUND = 0;
    private static final int DCU_REBOOT_PENDING = 5;
    private static final int DCU_SCAN_NO_UPDATES = 500;
    private static final int LENOVO_SCAN_NO_UPDATES = 10000;
    private static final int LENOVO_SCAN_UPDATES_FOUND = 10001;
    private static final String LENOVO_FIRMWARE_PACKAGE_TYPES = "3,4"; // 3 = BIOS, 4 = Firmware
    private static final String LENOVO_REBOOT_TYPES = "1,3,4,5";      // omitted => reboot type 0 only

    // Whole-token counts: "10 packages" must never read as zero.
    private static final Pattern LENOVO_PACKAGES_FOUND = Pattern.compile(
        "(?<![\\d.,])\\b[1-9]\\d*\\s+(?:applicable\\s+)?(?:update\\s+)?packages?\\b",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern LENOVO_NO_PACKAGES = Pattern.compile(
        "(?<![\\d.,])\\b0\\s+(?:applicable\\s+)?(?:update\\s+)?packages?\\b"
            + "|\\bno\\s+(?:applicable\\s+)?(?:updates?|packages?)\\b",
        Pattern.CASE_INSENSITIVE);

    private static final String WU_TITLE_PREFIX = "TITLE:";
    private static final String WU_DONE_MARKER = "DONE";

    private volatile Oem cachedOem = null;
    private final Object oemLock = new Object();
    private final AtomicBoolean pswuEnsured = new AtomicBoolean(false);

    /** Machine-wide firmware staleness verdict from one vendor-tool run. */
    public record FirmwareCheck(Driver.Status status, String message) {}

    // -------------------------------------------------------------------------
    // OEM detection
    // -------------------------------------------------------------------------

    /** A failed or blank WMI lookup returns UNKNOWN without caching, so the next scan retries. */
    public Oem detectOem() {
        Oem oem = cachedOem;
        if (oem != null) return oem;
        synchronized (oemLock) {
            if (cachedOem != null) return cachedOem;
            Oem queried = queryOem();
            if (queried == null) return Oem.UNKNOWN;
            cachedOem = queried;
            log.info("Detected OEM: {}", queried);
            return queried;
        }
    }

    /** Returns null when the manufacturer could not be read. */
    private Oem queryOem() {
        ProcessResult r;
        try {
            r = run("powershell.exe", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                "try { (Get-WmiObject Win32_ComputerSystem -ErrorAction Stop).Manufacturer } catch { exit 1 }");
        } catch (Exception e) {
            log.warn("OEM detection failed; will retry on next scan", e);
            return null;
        }
        String manufacturer = r.output == null ? "" : r.output.trim();
        if (r.exitCode != 0 || manufacturer.isEmpty() || manufacturer.indexOf('\n') >= 0) {
            log.warn("OEM detection unusable (exit {}, output '{}'); will retry on next scan", r.exitCode, manufacturer);
            return null;
        }
        String lower = manufacturer.toLowerCase();
        if (lower.contains("dell"))   return Oem.DELL;
        if (lower.contains("hp") || lower.contains("hewlett")) return Oem.HP;
        if (lower.contains("lenovo")) return Oem.LENOVO;
        return Oem.UNKNOWN;
    }

    public boolean isOemToolAvailable() {
        return switch (detectOem()) {
            case DELL    -> fileExists(DELL_DCU);
            case LENOVO  -> fileExists(LENOVO_THIN_INSTALLER)
                         || fileExists(LENOVO_SYSTEM_UPDATE);
            case HP      -> hpiaPath() != null;
            default      -> false;
        };
    }

    private String hpiaPath() {
        if (fileExists(HP_IMAGE_ASSISTANT))     return HP_IMAGE_ASSISTANT;
        if (fileExists(HP_IMAGE_ASSISTANT_X86)) return HP_IMAGE_ASSISTANT_X86;
        return null;
    }

    // -------------------------------------------------------------------------
    // Staleness check (called from WindowsUpdateCatalogService for Firmware class)
    // -------------------------------------------------------------------------

    public void checkFirmwareForUpdates(Driver driver) {
        checkFirmwareForUpdates(List.of(driver));
    }

    /**
     * OEM tools answer machine-wide, so the vendor CLI runs once and its verdict is applied to
     * every firmware driver. Without a vendor tool, one Windows Update firmware query runs and
     * pending titles are matched to device names in memory.
     */
    public void checkFirmwareForUpdates(List<Driver> drivers) {
        if (drivers.isEmpty()) return;
        try {
            FirmwareCheck check = checkFirmwareOnce();
            if (check != null) {
                for (Driver d : drivers) apply(d, check);
            } else {
                checkViaWindowsUpdateFirmware(drivers);
            }
        } catch (Exception e) {
            log.error("Firmware staleness check failed", e);
            FirmwareCheck failed = new FirmwareCheck(Driver.Status.UNKNOWN,
                "Firmware staleness check failed: " + e.getMessage());
            for (Driver d : drivers) apply(d, failed);
        }
    }

    /** Runs the vendor tool once; returns null when no vendor tool applies (per-device fallback needed). */
    FirmwareCheck checkFirmwareOnce() throws Exception {
        return switch (detectOem()) {
            case DELL    -> checkViaDell();
            case LENOVO  -> checkViaLenovo();
            case HP      -> checkViaHp();
            default      -> null;
        };
    }

    private static void apply(Driver driver, FirmwareCheck check) {
        driver.setStatus(check.status());
        driver.setStatusMessage(check.message());
    }

    // -------------------------------------------------------------------------
    // Update (called from DriverUpdateService for Firmware class)
    // -------------------------------------------------------------------------

    public UpdateResult triggerFirmwareUpdate(Driver driver) {
        try {
            return switch (detectOem()) {
                case DELL    -> updateViaDell(driver);
                case LENOVO  -> updateViaLenovo(driver);
                case HP      -> updateViaHp(driver);
                default      -> updateViaWindowsUpdateFirmware(driver);
            };
        } catch (Exception e) {
            log.error("Firmware update failed for '{}'", driver.getDeviceName(), e);
            return new UpdateResult(driver.getDeviceId(), false,
                "Firmware update failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Dell Command Update
    // -------------------------------------------------------------------------

    private FirmwareCheck checkViaDell() throws Exception {
        if (!fileExists(DELL_DCU)) {
            log.info("Dell DCU not found — falling back to Windows Update firmware check");
            return null;
        }

        // DCU reference guide: 500 = no updates found; 0 = success (a scan that found no updates
        // reports 500, so 0 means updates were found); 5 = reboot pending from a prior operation.
        ProcessResult result = run(DELL_DCU,
            "/scan", "-updateType=bios,firmware", "-silent");

        if (result.exitCode == DCU_SCAN_UPDATES_FOUND) {
            return new FirmwareCheck(Driver.Status.STALE, "Firmware update available (Dell Command Update).");
        }
        if (result.exitCode == DCU_SCAN_NO_UPDATES) {
            return new FirmwareCheck(Driver.Status.UP_TO_DATE, "Firmware is current (Dell Command Update).");
        }
        if (result.exitCode == DCU_REBOOT_PENDING) {
            return new FirmwareCheck(Driver.Status.UNKNOWN,
                "Dell Command Update cannot scan: a reboot from a previous update is pending.");
        }
        log.warn("Dell DCU scan unexpected exit {}:\n{}", result.exitCode, result.output);
        return new FirmwareCheck(Driver.Status.UNKNOWN, "Dell DCU scan exited with code " + result.exitCode);
    }

    private UpdateResult updateViaDell(Driver driver) throws Exception {
        if (!fileExists(DELL_DCU)) {
            log.info("Dell DCU not found — falling back to Windows Update firmware update");
            return updateViaWindowsUpdateFirmware(driver);
        }

        // Exit 0=success, 1=reboot needed (still a success), others=failure
        ProcessResult result = run(DELL_DCU,
            "/applyUpdates",
            "-updateType=bios,firmware",
            "-reboot=disable",
            "-autoSuspendBitLocker=enable",
            "-silent");

        boolean success = result.exitCode == 0 || result.exitCode == 1;
        String msg = success
            ? "Firmware updated via Dell Command Update"
                + (result.exitCode == 1 ? " — reboot required to complete." : ".")
            : "Dell DCU apply failed (exit " + result.exitCode + ")";
        if (!success) log.error("Dell DCU update failed for '{}' (exit {}):\n{}", driver.getDeviceName(), result.exitCode, result.output);
        return new UpdateResult(driver.getDeviceId(), success, msg);
    }

    // -------------------------------------------------------------------------
    // Lenovo Thin Installer / System Update
    // -------------------------------------------------------------------------

    /**
     * Thin Installer only: System Update's documented CLI (tvsu.exe -action LIST) shows an
     * interactive pick list and has no documented return codes, so it cannot answer a silent check.
     */
    private FirmwareCheck checkViaLenovo() throws Exception {
        if (!fileExists(LENOVO_THIN_INSTALLER)) {
            log.info("Lenovo Thin Installer not found — falling back to Windows Update firmware check");
            return null;
        }

        // -action SCAN only assesses applicability (read-only). Filters need Thin Installer 1.3.0041+.
        ProcessResult result = run(LENOVO_THIN_INSTALLER,
            "/CM", "-search", "A", "-action", "SCAN",
            "-packagetypes", LENOVO_FIRMWARE_PACKAGE_TYPES,
            "-includerebootpackages", LENOVO_REBOOT_TYPES, "-noicon");

        if (result.exitCode == LENOVO_SCAN_UPDATES_FOUND) return lenovoStale();
        if (result.exitCode == LENOVO_SCAN_NO_UPDATES)    return lenovoCurrent();
        if (result.exitCode != 0) {
            log.warn("Lenovo Thin Installer unexpected exit {}:\n{}", result.exitCode, result.output);
            return new FirmwareCheck(Driver.Status.UNKNOWN,
                "Lenovo Thin Installer exited with code " + result.exitCode);
        }
        // Exit 0 comes from builds that predate the documented SCAN codes: trust only explicit text.
        String output = result.output == null ? "" : result.output;
        if (LENOVO_PACKAGES_FOUND.matcher(output).find()) return lenovoStale();
        if (LENOVO_NO_PACKAGES.matcher(output).find())    return lenovoCurrent();
        log.warn("Lenovo Thin Installer output not recognised:\n{}", output);
        return new FirmwareCheck(Driver.Status.UNKNOWN,
            "Firmware status could not be determined from Lenovo Thin Installer output.");
    }

    private static FirmwareCheck lenovoStale() {
        return new FirmwareCheck(Driver.Status.STALE, "Firmware update available (Lenovo Thin Installer).");
    }

    private static FirmwareCheck lenovoCurrent() {
        return new FirmwareCheck(Driver.Status.UP_TO_DATE, "Firmware is current (Lenovo Thin Installer).");
    }

    private UpdateResult updateViaLenovo(Driver driver) throws Exception {
        String tool = fileExists(LENOVO_THIN_INSTALLER)
            ? LENOVO_THIN_INSTALLER : null;
        if (tool == null && fileExists(LENOVO_SYSTEM_UPDATE))
            tool = LENOVO_SYSTEM_UPDATE;

        if (tool == null) {
            return updateViaWindowsUpdateFirmware(driver);
        }

        ProcessResult result = run(tool,
            "/CM", "-search", "A", "-action", "INSTALL",
            "-packagetypes", LENOVO_FIRMWARE_PACKAGE_TYPES, "-includerebootpackages", LENOVO_REBOOT_TYPES);

        boolean success = result.exitCode == 0 || result.exitCode == 3010;
        String msg = success
            ? "Firmware updated via Lenovo System Update"
                + (result.exitCode == 3010 ? " — reboot required." : ".")
            : "Lenovo update failed (exit " + result.exitCode + ")";
        if (!success) log.error("Lenovo update failed for '{}' (exit {}):\n{}", driver.getDeviceName(), result.exitCode, result.output);
        return new UpdateResult(driver.getDeviceId(), success, msg);
    }

    // -------------------------------------------------------------------------
    // HP Image Assistant (HPIA)
    // HPIA scan exit codes: 0 = no recommendations, 1 = updates available, other = error
    // HPIA install exit codes: 0 = success, 1 = success + reboot needed, other = failure
    // -------------------------------------------------------------------------

    private FirmwareCheck checkViaHp() throws Exception {
        String tool = hpiaPath();
        if (tool == null) {
            log.info("HP Image Assistant not found — falling back to Windows Update firmware check");
            return null;
        }

        ProcessResult result = run(tool,
            "/Operation:Analyze", "/Category:BIOS,Firmware",
            "/Selection:All", "/Action:List", "/Silent");

        if (result.exitCode == 1) {
            return new FirmwareCheck(Driver.Status.STALE, "Firmware update available (HP Image Assistant).");
        }
        if (result.exitCode == 0) {
            return new FirmwareCheck(Driver.Status.UP_TO_DATE, "Firmware is current (HP Image Assistant).");
        }
        log.warn("HP Image Assistant scan unexpected exit {}:\n{}", result.exitCode, result.output);
        return new FirmwareCheck(Driver.Status.UNKNOWN, "HP Image Assistant scan exited with code " + result.exitCode);
    }

    private UpdateResult updateViaHp(Driver driver) throws Exception {
        String tool = hpiaPath();
        if (tool == null) {
            log.info("HP Image Assistant not found — falling back to Windows Update firmware update");
            return updateViaWindowsUpdateFirmware(driver);
        }

        ProcessResult result = run(tool,
            "/Operation:Analyze", "/Category:BIOS,Firmware",
            "/Selection:All", "/Action:Install", "/Silent", "/RebootNeeded:No");

        boolean success = result.exitCode == 0 || result.exitCode == 1;
        String msg = success
            ? "Firmware updated via HP Image Assistant"
                + (result.exitCode == 1 ? " — reboot required to complete." : ".")
            : "HP Image Assistant failed (exit " + result.exitCode + ")";
        if (!success) log.error("HP Image Assistant update failed for '{}' (exit {}):\n{}", driver.getDeviceName(), result.exitCode, result.output);
        return new UpdateResult(driver.getDeviceId(), success, msg);
    }

    // -------------------------------------------------------------------------
    // PSWindowsUpdate firmware category fallback (unknown OEMs)
    // -------------------------------------------------------------------------

    /** One catalog query per scan; titles are matched to device names in memory (case-insensitive substring). */
    private void checkViaWindowsUpdateFirmware(List<Driver> drivers) throws Exception {
        ensurePSWindowsUpdate();
        String result = runPowerShell("""
            try {
                Import-Module PSWindowsUpdate -ErrorAction Stop;
                $all = Get-WindowsUpdate -Category 'Firmware' -ErrorAction Stop;
                foreach ($u in $all) { Write-Output ('%s' + $u.Title) }
                Write-Output '%s'
            } catch {
                Write-Output ('QUERY_ERROR|' + ($_.Exception.Message -replace '\\s+',' '))
            }
            """.formatted(WU_TITLE_PREFIX, WU_DONE_MARKER));

        List<String> lines = result.lines().map(String::trim).toList();
        if (!lines.contains(WU_DONE_MARKER)) {
            log.warn("PSWindowsUpdate firmware check inconclusive:\n{}", result);
            FirmwareCheck inconclusive = new FirmwareCheck(Driver.Status.UNKNOWN,
                "Windows Update firmware query failed: "
                    + result.lines().findFirst().orElse("no output").replaceFirst("^QUERY_ERROR\\|", ""));
            for (Driver d : drivers) apply(d, inconclusive);
            return;
        }
        List<String> titles = lines.stream()
            .filter(l -> l.startsWith(WU_TITLE_PREFIX))
            .map(l -> l.substring(WU_TITLE_PREFIX.length()).toLowerCase(Locale.ROOT))
            .toList();
        for (Driver d : drivers) {
            String name = d.getDeviceName();
            if (name == null || name.isBlank()) {
                apply(d, new FirmwareCheck(Driver.Status.UNKNOWN, "Firmware check skipped: device has no name."));
                continue;
            }
            String needle = name.toLowerCase(Locale.ROOT);
            boolean pending = titles.stream().anyMatch(t -> t.contains(needle));
            apply(d, pending
                ? new FirmwareCheck(Driver.Status.STALE, "Firmware update available via Windows Update.")
                : new FirmwareCheck(Driver.Status.UP_TO_DATE, "Firmware is current (Windows Update firmware check)."));
        }
    }

    private UpdateResult updateViaWindowsUpdateFirmware(Driver driver) throws Exception {
        ensurePSWindowsUpdate();
        String psCmd = String.format("""
            Import-Module PSWindowsUpdate -ErrorAction Stop;
            $all = Get-WindowsUpdate -Category 'Firmware' -ErrorAction SilentlyContinue;
            $pat = [Regex]::Escape('%s');
            $target = $all | Where-Object { $_.Title -match $pat } | Select-Object -First 1;
            if ($target) {
                $r = Install-WindowsUpdate -KBArticleID $target.KBArticleIDs[0] `
                    -AcceptAll -AutoReboot:$false -IgnoreReboot -ErrorAction SilentlyContinue;
                if ($r) { Write-Output ('SUCCESS: ' + ($r | Select-Object -ExpandProperty Title)) }
                else    { Write-Output 'NONE' }
            } else {
                Write-Output 'NONE'
            }
            """, escapeForPowerShell(driver.getDeviceName()));

        String result = runPowerShell(psCmd);
        if (requiresElevation(result)) {
            log.error("PSWindowsUpdate firmware update for '{}' requires elevation — restart as Administrator.", driver.getDeviceName());
            return new UpdateResult(driver.getDeviceId(), false,
                "Administrator rights required to install updates. Restart the application as Administrator.");
        }
        if (result.startsWith("SUCCESS")) {
            return new UpdateResult(driver.getDeviceId(), true,
                "Firmware updated via Windows Update: " + result.replace("SUCCESS: ", ""));
        }
        String lastLine = result.lines().map(String::trim).filter(l -> !l.isEmpty())
            .reduce((a, b) -> b).orElse("");
        if (lastLine.equals("NONE")) {
            log.warn("PSWindowsUpdate found no firmware update for '{}'.", driver.getDeviceName());
            return new UpdateResult(driver.getDeviceId(), false,
                "No firmware update found in Windows Update catalog.");
        }
        log.error("PSWindowsUpdate firmware update inconclusive for '{}':\n{}", driver.getDeviceName(), result);
        return new UpdateResult(driver.getDeviceId(), false,
            "Firmware update via Windows Update inconclusive: " + result);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    record ProcessResult(int exitCode, String output) {}

    boolean fileExists(String path) {
        return Files.exists(Path.of(path));
    }

    ProcessResult run(String... command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder out = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) out.append(line).append("\n");
        }
        return new ProcessResult(process.waitFor(), out.toString().trim());
    }

    public void ensurePSWindowsUpdate() {
        if (!pswuEnsured.compareAndSet(false, true)) return;
        try {
            runPowerShell("""
                if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
                    Install-Module -Name PSWindowsUpdate -Scope CurrentUser -Force -AllowClobber
                }
                """);
            log.info("PSWindowsUpdate module is available.");
        } catch (Exception e) {
            pswuEnsured.set(false); // allow retry on next call if it failed
            log.warn("Could not ensure PSWindowsUpdate module", e);
        }
    }

    private String runPowerShell(String psCmd) throws Exception {
        ProcessResult r = run(
            "powershell.exe", "-NonInteractive", "-NoProfile",
            "-ExecutionPolicy", "Bypass", "-Command", psCmd
        );
        return r.output;
    }

    private boolean requiresElevation(String output) {
        return output.contains("run an elevated")
            || output.contains("AccessDenied")
            || output.contains("PermissionDenied")
            || output.contains("Administrator rights are required");
    }

    private String escapeForPowerShell(String input) {
        return input.replace("'", "''").replace("\"", "`\"");
    }
}
