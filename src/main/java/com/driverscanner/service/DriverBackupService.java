package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.logging.Logger;

/**
 * Backs up the current driver INF package via pnputil before an update,
 * and restores it from backup for rollback.
 *
 * Backups are stored under %LOCALAPPDATA%\DriverDashboard\Backups\<deviceId>\<timestamp>.
 * Requires Administrator privileges for pnputil /export-driver and /add-driver.
 */
@Service
public class DriverBackupService {

    private static final Logger log = Logger.getLogger(DriverBackupService.class.getName());
    private static final DateTimeFormatter TIMESTAMP_FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private final Path backupRoot;
    private final int recentDays;

    @Autowired
    public DriverBackupService(@Value("${driver.backup.recent-days:7}") int recentDays) {
        this(Path.of(System.getenv("LOCALAPPDATA") + "\\DriverDashboard\\Backups"), recentDays);
    }

    DriverBackupService(Path backupRoot, int recentDays) {
        this.backupRoot = backupRoot.toAbsolutePath().normalize();
        this.recentDays = recentDays;
    }

    public record BackupStatus(boolean hasRecentBackup, String backupPath, LocalDateTime timestamp) {}

    /**
     * Exports the current driver package for the given device to a timestamped backup folder.
     * Returns the backup directory path, or throws if the INF cannot be found or export fails.
     */
    public String backupDriver(Driver driver) throws Exception {
        String infName = findInfName(driver);
        if (infName == null || infName.equals("NONE")) {
            throw new Exception("Could not locate INF for device: " + driver.getDeviceName());
        }

        String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);
        String backupPath = backupRoot.resolve(sanitizeId(driver.getDeviceId())).resolve(timestamp).toString();
        Files.createDirectories(Path.of(backupPath));

        ProcessBuilder pb = new ProcessBuilder("pnputil.exe", "/export-driver", infName, backupPath);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) output.append(line).append("\n");
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new Exception("pnputil /export-driver failed (exit " + exitCode + "): " + output.toString().trim());
        }

        log.info("Driver backed up to: " + backupPath + " (INF: " + infName + ")");
        return backupPath;
    }

    /**
     * Rolls back a driver by re-installing the backed-up INF package via pnputil.
     * Returns true on success. The path comes from the client, so it must resolve
     * strictly inside the backup root (IllegalArgumentException otherwise).
     */
    public boolean rollbackDriver(String backupPath) throws Exception {
        Path inf = findInfInBackup(resolveBackupPath(backupPath));
        if (inf == null) {
            throw new Exception("No .inf file found in backup: " + backupPath);
        }

        ProcessBuilder pb = new ProcessBuilder("pnputil.exe", "/add-driver", inf.toString(), "/install");
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) output.append(line).append("\n");
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new Exception("pnputil /add-driver failed (exit " + exitCode + "): " + output.toString().trim());
        }

        log.info("Driver rolled back from: " + backupPath);
        return true;
    }

    /**
     * Normalises a client-supplied backup path and rejects anything that is not a
     * descendant of the backup root, including traversal and junction/symlink escapes.
     */
    Path resolveBackupPath(String backupPath) {
        if (backupPath == null || backupPath.isBlank()) {
            throw new IllegalArgumentException("backupPath is required");
        }
        Path candidate = Path.of(backupPath).toAbsolutePath().normalize();
        if (!isStrictlyInside(candidate, backupRoot)) {
            throw new IllegalArgumentException("backupPath is outside the backup directory");
        }
        if (!Files.exists(candidate)) return candidate;
        Path real;
        try {
            real = candidate.toRealPath();
            if (!isStrictlyInside(real, backupRoot.toRealPath())) {
                throw new IllegalArgumentException("backupPath is outside the backup directory");
            }
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("backupPath could not be resolved", e);
        }
        return real;
    }

    private static boolean isStrictlyInside(Path candidate, Path root) {
        return candidate.startsWith(root) && !candidate.equals(root);
    }

    public BackupStatus getBackupStatus(Driver driver) {
        String path = findRecentBackup(driver);
        if (path == null) return new BackupStatus(false, null, null);
        return new BackupStatus(true, path,
            LocalDateTime.parse(Path.of(path).getFileName().toString(), TIMESTAMP_FMT));
    }

    /**
     * Returns the path of the most recent backup for this driver if one exists
     * within the last driver.backup.recent-days days, or null otherwise.
     */
    public String findRecentBackup(Driver driver) {
        try {
            Path deviceBackupDir = backupRoot.resolve(sanitizeId(driver.getDeviceId()));
            if (!Files.exists(deviceBackupDir)) return null;

            DateTimeFormatter fmt = TIMESTAMP_FMT;
            LocalDateTime cutoff = LocalDateTime.now().minusDays(recentDays);

            try (var stream = Files.list(deviceBackupDir)) {
                return stream
                    .filter(Files::isDirectory)
                    .filter(p -> {
                        try {
                            return LocalDateTime.parse(p.getFileName().toString(), fmt).isAfter(cutoff);
                        } catch (Exception e) {
                            return false;
                        }
                    })
                    .max(java.util.Comparator.comparing(Path::getFileName))
                    .map(Path::toString)
                    .orElse(null);
            }
        } catch (Exception e) {
            log.warning("Could not check for recent backup for " + driver.getDeviceName() + ": " + e.getMessage());
            return null;
        }
    }

    private String findInfName(Driver driver) throws Exception {
        String lookupId = driver.getRawDeviceId() != null ? driver.getRawDeviceId() : driver.getDeviceId();
        String psCmd = String.format("""
            $d = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceID -eq '%s' } | Select-Object -First 1;
            if ($d -and $d.InfName) { Write-Output $d.InfName } else { Write-Output 'NONE' }
            """, escapeForPowerShell(lookupId));

        ProcessBuilder pb = new ProcessBuilder(
            "powershell.exe", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd
        );
        pb.redirectErrorStream(true);
        Process process = pb.start();

        String result;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            result = reader.lines().map(String::trim).filter(l -> !l.isEmpty()).findFirst().orElse("NONE");
        }
        process.waitFor();
        return result;
    }

    private Path findInfInBackup(Path backupPath) throws Exception {
        try (var stream = Files.walk(backupPath, 2)) {
            return stream.filter(p -> p.toString().endsWith(".inf")).findFirst().orElse(null);
        }
    }

    private String sanitizeId(String deviceId) {
        return deviceId.replaceAll("[\\\\/:*?\"<>|]", "_");
    }

    private String escapeForPowerShell(String input) {
        return input.replace("'", "''").replace("\"", "`\"");
    }
}
