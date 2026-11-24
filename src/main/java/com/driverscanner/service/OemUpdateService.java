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
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Handles firmware staleness checks and updates via OEM-specific CLI tools.
 *
 * OEM detection uses Win32_ComputerSystem.Manufacturer via WMI (cached after first call).
 * Tool paths and exit-code semantics per OEM:
 *
 *   Dell  — Dell Command Update (dcu-cli.exe)
 *             scan exit 5 = updates available, 0/500 = none
 *             apply exit 0 = success, 1 = reboot needed (treated as success)
 *
 *   Lenovo — Lenovo Thin Installer (ThinInstaller.exe)
 *             exit 3010 = success + reboot needed, 0 = success, non-zero = fail
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

    private Oem cachedOem = null;
    private final AtomicBoolean pswuEnsured = new AtomicBoolean(false);

    // -------------------------------------------------------------------------
    // OEM detection
    // -------------------------------------------------------------------------

    public Oem detectOem() {
        if (cachedOem != null) return cachedOem;
        try {
            String manufacturer = runPowerShell(
                "(Get-WmiObject Win32_ComputerSystem).Manufacturer"
            ).toLowerCase();
            if (manufacturer.contains("dell"))   cachedOem = Oem.DELL;
            else if (manufacturer.contains("hp") || manufacturer.contains("hewlett"))
                                                 cachedOem = Oem.HP;
            else if (manufacturer.contains("lenovo")) cachedOem = Oem.LENOVO;
            else                                 cachedOem = Oem.UNKNOWN;
        } catch (Exception e) {
            log.warn("OEM detection failed", e);
            cachedOem = Oem.UNKNOWN;
        }
        log.info("Detected OEM: {}", cachedOem);
        return cachedOem;
    }

    public boolean isOemToolAvailable() {
        return switch (detectOem()) {
            case DELL    -> Files.exists(Path.of(DELL_DCU));
            case LENOVO  -> Files.exists(Path.of(LENOVO_THIN_INSTALLER))
                         || Files.exists(Path.of(LENOVO_SYSTEM_UPDATE));
            case HP      -> hpiaPath() != null;
            default      -> false;
        };
    }

    private String hpiaPath() {
        if (Files.exists(Path.of(HP_IMAGE_ASSISTANT)))     return HP_IMAGE_ASSISTANT;
        if (Files.exists(Path.of(HP_IMAGE_ASSISTANT_X86))) return HP_IMAGE_ASSISTANT_X86;
        return null;
    }

    // -------------------------------------------------------------------------
    // Staleness check (called from WindowsUpdateCatalogService for Firmware class)
    // -------------------------------------------------------------------------

    public void checkFirmwareForUpdates(Driver driver) {
        try {
            switch (detectOem()) {
                case DELL    -> checkViaDell(driver);
                case LENOVO  -> checkViaLenovo(driver);
                case HP      -> checkViaHp(driver);
                default      -> checkViaWindowsUpdateFirmware(driver);
            }
        } catch (Exception e) {
            log.error("Firmware staleness check failed for '{}'", driver.getDeviceName(), e);
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Firmware staleness check failed: " + e.getMessage());
        }
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

    private void checkViaDell(Driver driver) throws Exception {
        if (!Files.exists(Path.of(DELL_DCU))) {
            log.info("Dell DCU not found — falling back to Windows Update firmware check");
            checkViaWindowsUpdateFirmware(driver);
            return;
        }

        // DCU scan exit codes: 0=no updates, 5=updates available, 500=no applicable updates
        ProcessResult result = run(DELL_DCU,
            "/scan", "-updateType=bios,firmware", "-silent");

        if (result.exitCode == 5) {
            driver.setStatus(Driver.Status.STALE);
            driver.setStatusMessage("Firmware update available (Dell Command Update).");
        } else if (result.exitCode == 0 || result.exitCode == 500) {
            driver.setStatus(Driver.Status.UP_TO_DATE);
            driver.setStatusMessage("Firmware is current (Dell Command Update).");
        } else {
            log.warn("Dell DCU scan unexpected exit {} for '{}':\n{}", result.exitCode, driver.getDeviceName(), result.output);
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Dell DCU scan exited with code " + result.exitCode);
        }
    }

    private UpdateResult updateViaDell(Driver driver) throws Exception {
        if (!Files.exists(Path.of(DELL_DCU))) {
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

    private void checkViaLenovo(Driver driver) throws Exception {
        String tool = Files.exists(Path.of(LENOVO_THIN_INSTALLER))
            ? LENOVO_THIN_INSTALLER : null;
        if (tool == null && Files.exists(Path.of(LENOVO_SYSTEM_UPDATE)))
            tool = LENOVO_SYSTEM_UPDATE;

        if (tool == null) {
            log.info("Lenovo update tool not found — falling back to Windows Update firmware check");
            checkViaWindowsUpdateFirmware(driver);
            return;
        }

        // Thin Installer: /CM -search A -action INSTALL -packagetypes 1 (BIOS/firmware) -noreboot
        // Non-zero exit means updates were found/applied; 0 = nothing to do
        ProcessResult result = run(tool,
            "/CM", "-search", "A", "-action", "INSTALL",
            "-packagetypes", "1", "-noreboot", "-includerebootpackages", "0");

        if (result.exitCode == 0) {
            driver.setStatus(Driver.Status.UP_TO_DATE);
            driver.setStatusMessage("Firmware is current (Lenovo System Update).");
        } else if (result.exitCode == 3010 || result.output.toLowerCase().contains("success")) {
            driver.setStatus(Driver.Status.STALE);
            driver.setStatusMessage("Firmware update available (Lenovo System Update).");
        } else {
            log.warn("Lenovo update tool unexpected exit {} for '{}':\n{}", result.exitCode, driver.getDeviceName(), result.output);
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Lenovo update tool exited with code " + result.exitCode);
        }
    }

    private UpdateResult updateViaLenovo(Driver driver) throws Exception {
        String tool = Files.exists(Path.of(LENOVO_THIN_INSTALLER))
            ? LENOVO_THIN_INSTALLER : null;
        if (tool == null && Files.exists(Path.of(LENOVO_SYSTEM_UPDATE)))
            tool = LENOVO_SYSTEM_UPDATE;

        if (tool == null) {
            return updateViaWindowsUpdateFirmware(driver);
        }

        ProcessResult result = run(tool,
            "/CM", "-search", "A", "-action", "INSTALL",
            "-packagetypes", "1", "-includerebootpackages", "3");

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

    private void checkViaHp(Driver driver) throws Exception {
        String tool = hpiaPath();
        if (tool == null) {
            log.info("HP Image Assistant not found — falling back to Windows Update firmware check");
            checkViaWindowsUpdateFirmware(driver);
            return;
        }

        ProcessResult result = run(tool,
            "/Operation:Analyze", "/Category:BIOS,Firmware",
            "/Selection:All", "/Action:List", "/Silent");

        if (result.exitCode == 1) {
            driver.setStatus(Driver.Status.STALE);
            driver.setStatusMessage("Firmware update available (HP Image Assistant).");
        } else if (result.exitCode == 0) {
            driver.setStatus(Driver.Status.UP_TO_DATE);
            driver.setStatusMessage("Firmware is current (HP Image Assistant).");
        } else {
            log.warn("HP Image Assistant scan unexpected exit {} for '{}':\n{}", result.exitCode, driver.getDeviceName(), result.output);
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("HP Image Assistant scan exited with code " + result.exitCode);
        }
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

    private void checkViaWindowsUpdateFirmware(Driver driver) throws Exception {
        ensurePSWindowsUpdate();
        String psCmd = String.format("""
            Import-Module PSWindowsUpdate -ErrorAction Stop;
            $all = Get-WindowsUpdate -Category 'Firmware' -ErrorAction SilentlyContinue;
            $pat = [Regex]::Escape('%s');
            $u = $all | Where-Object { $_.Title -match $pat };
            if ($u) { Write-Output 'STALE' } else { Write-Output 'CURRENT' }
            """, escapeForPowerShell(driver.getDeviceName()));

        String result = runPowerShell(psCmd);
        if (result.contains("STALE")) {
            driver.setStatus(Driver.Status.STALE);
            driver.setStatusMessage("Firmware update available via Windows Update.");
        } else if (result.contains("CURRENT")) {
            driver.setStatus(Driver.Status.UP_TO_DATE);
            driver.setStatusMessage("Firmware is current (Windows Update firmware check).");
        } else {
            log.warn("PSWindowsUpdate firmware check inconclusive for '{}':\n{}", driver.getDeviceName(), result);
            driver.setStatus(Driver.Status.UNKNOWN);
            driver.setStatusMessage("Firmware check inconclusive: " + result.lines().findFirst().orElse("no output"));
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

    private record ProcessResult(int exitCode, String output) {}

    private ProcessResult run(String... command) throws Exception {
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
