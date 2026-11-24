package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.logging.Logger;

/**
 * Backs up the current driver INF package via pnputil before an update,
 * and restores it from backup for rollback.
 *
 * Backups are stored under driver.backup.root\<deviceId>\<timestamp>
 * (default %ProgramData%\DriverDashboard\Backups). Because rollback installs from there
 * with admin rights, every folder this service creates is locked to SYSTEM/Administrators,
 * and the tree is re-verified (BackupAclGuard) before a backup is written, reused or installed.
 * Requires Administrator privileges for pnputil /export-driver and /add-driver.
 */
@Service
public class DriverBackupService {

    private static final Logger log = Logger.getLogger(DriverBackupService.class.getName());
    private static final DateTimeFormatter TIMESTAMP_FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");
    private static final String STAGING_PREFIX = ".rollback-";

    private final Path backupRoot;
    private final int recentDays;
    private final BackupAclGuard aclGuard;

    @Autowired
    public DriverBackupService(
            @Value("${driver.backup.root:}") String backupRoot,
            @Value("${driver.backup.recent-days:7}") int recentDays) {
        this(resolveRoot(backupRoot), recentDays, BackupAclGuard.windows());
    }

    DriverBackupService(Path backupRoot, int recentDays, BackupAclGuard aclGuard) {
        this.backupRoot = backupRoot.toAbsolutePath().normalize();
        this.recentDays = recentDays;
        this.aclGuard = aclGuard;
    }

    /** A backup folder that a non-admin process could have written to; its contents must not reach pnputil. */
    public static class InsecureBackupException extends RuntimeException {
        public InsecureBackupException(String message) {
            super(message);
        }
    }

    /** A blank ProgramData leaves a drive-less path, which would silently resolve against the working dir. */
    static Path resolveRoot(String configured) {
        if (configured == null || configured.isBlank() || configured.contains("${")) {
            throw new IllegalStateException("driver.backup.root is not set (and ProgramData is unavailable)");
        }
        Path root;
        try {
            root = Path.of(configured.trim());
        } catch (java.nio.file.InvalidPathException e) {
            throw new IllegalStateException("driver.backup.root is not a valid path: " + configured, e);
        }
        if (!root.isAbsolute()) {
            throw new IllegalStateException("driver.backup.root must be an absolute path, got: " + configured);
        }
        return root;
    }

    public record BackupStatus(boolean hasRecentBackup, String backupPath, LocalDateTime timestamp) {}

    record ProcessResult(int exitCode, String output) {}

    /**
     * Exports the current driver package for the given device to a timestamped backup folder.
     * Returns the backup directory path, or throws if the INF cannot be found or export fails.
     */
    public String backupDriver(Driver driver) throws Exception {
        String infName = findInfName(driver);
        if (infName == null || infName.equals("NONE")) {
            throw new Exception("Could not locate INF for device: " + driver.getDeviceName());
        }

        Path deviceDir = deviceBackupDir(driver.getDeviceId());
        createSecured(deviceDir);
        Path realDeviceDir = deviceDir.toRealPath();
        aclGuard.requireSecure(backupRoot.toRealPath(), realDeviceDir);

        String timestamp = LocalDateTime.now().format(TIMESTAMP_FMT);
        String backupPath = Files.createDirectories(realDeviceDir.resolve(timestamp)).toString();

        ProcessResult result = runProcess(List.of("pnputil.exe", "/export-driver", infName, backupPath));
        if (result.exitCode() != 0) {
            throw new Exception("pnputil /export-driver failed (exit " + result.exitCode() + "): " + result.output().trim());
        }

        log.info("Driver backed up to: " + backupPath + " (INF: " + infName + ")");
        return backupPath;
    }

    /**
     * Rolls back a driver by re-installing the backed-up INF package via pnputil.
     * Returns true on success. The path comes from the client, so it must resolve
     * strictly inside this device's backup folder (IllegalArgumentException otherwise).
     */
    public boolean rollbackDriver(String deviceId, String backupPath) throws Exception {
        Path backupDir = resolveBackupPath(deviceId, backupPath);
        Path realRoot = backupRoot.toRealPath();
        Path realDeviceDir = deviceBackupDir(deviceId).toRealPath();
        aclGuard.requireSecure(realRoot, realDeviceDir);

        // pnputil gets a private copy taken after the checks, so the validated package cannot be swapped underneath it
        Path staging = Files.createTempDirectory(realDeviceDir, STAGING_PREFIX).toRealPath();
        try {
            copyTree(backupDir, staging);
            aclGuard.requireSecure(realRoot, realDeviceDir, staging);
            Path inf = findInfInBackup(staging, staging);
            if (inf == null) {
                throw new Exception("No .inf file found in backup: " + backupPath);
            }

            ProcessResult result = runProcess(List.of("pnputil.exe", "/add-driver", inf.toString(), "/install"));
            if (result.exitCode() != 0) {
                throw new Exception("pnputil /add-driver failed (exit " + result.exitCode() + "): " + result.output().trim());
            }
        } finally {
            deleteTree(staging);
        }

        log.info("Driver rolled back from: " + backupPath);
        return true;
    }

    /**
     * Creates any missing folders down to dir, locking each down before anything is placed in it.
     * Folders that already exist (an older build's, or one planted by another process) are left
     * untouched and only ever used if BackupAclGuard accepts them.
     */
    private void createSecured(Path dir) throws Exception {
        if (Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) return;
        Path parent = dir.getParent();
        if (parent != null) createSecured(parent);
        try {
            Files.createDirectory(dir);
        } catch (FileAlreadyExistsException raced) {
            return;
        }
        String admins = "*" + BackupAclGuard.ADMINISTRATORS_SID;
        for (List<String> args : List.of(
                List.of("/inheritance:r", "/grant:r", "*" + BackupAclGuard.SYSTEM_SID + ":(OI)(CI)F", admins + ":(OI)(CI)F"),
                List.of("/setowner", admins))) {
            List<String> cmd = new ArrayList<>(List.of("icacls.exe", dir.toString()));
            cmd.addAll(args);
            ProcessResult r = runProcess(cmd);
            if (r.exitCode() != 0) {
                // left in place it would keep its inherited ACL and fail the guard on every later run
                Files.deleteIfExists(dir);
                throw new Exception("icacls could not secure " + dir + " (exit " + r.exitCode() + "): " + r.output().trim());
            }
        }
    }

    /** Copies without following links; any link or reparse point (e.g. a junction) aborts the rollback. */
    private static void copyTree(Path src, Path dst) throws IOException {
        Path realSrc = src.toRealPath();
        try (var stream = Files.walk(realSrc)) {
            for (Path p : (Iterable<Path>) stream::iterator) {
                BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                if (a.isSymbolicLink() || a.isOther()) {
                    throw new IllegalArgumentException("Backup contains a link or reparse point: " + realSrc.relativize(p));
                }
                Path target = dst.resolve(realSrc.relativize(p).toString());
                if (a.isDirectory()) Files.createDirectories(target);
                else Files.copy(p, target, LinkOption.NOFOLLOW_LINKS);
            }
        }
    }

    private static void deleteTree(Path dir) {
        try (var stream = Files.walk(dir)) {
            for (Path p : stream.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
        } catch (IOException | UncheckedIOException e) {
            log.warning("Could not remove rollback staging folder " + dir + ": " + e.getMessage());
        }
    }

    /**
     * Normalises a client-supplied backup path and rejects anything that is not a
     * descendant of the given device's backup folder, including traversal, another
     * device's folder, and junction/symlink escapes.
     */
    Path resolveBackupPath(String deviceId, String backupPath) {
        if (backupPath == null || backupPath.isBlank()) {
            throw new IllegalArgumentException("backupPath is required");
        }
        Path deviceDir = deviceBackupDir(deviceId);
        Path candidate;
        try {
            candidate = Path.of(backupPath).toAbsolutePath().normalize();
        } catch (java.nio.file.InvalidPathException e) {
            throw new IllegalArgumentException("backupPath is not a valid path", e);
        }
        if (!isStrictlyInside(candidate, deviceDir)) {
            throw new IllegalArgumentException("backupPath is outside this device's backup directory");
        }
        if (!Files.exists(candidate)) return candidate;
        Path real;
        try {
            real = candidate.toRealPath();
            Path realDeviceDir = deviceDir.toRealPath();
            if (!isStrictlyInside(realDeviceDir, backupRoot.toRealPath()) || !isStrictlyInside(real, realDeviceDir)) {
                throw new IllegalArgumentException("backupPath is outside this device's backup directory");
            }
        } catch (java.io.IOException e) {
            throw new IllegalArgumentException("backupPath could not be resolved", e);
        }
        return real;
    }

    /** The device's own folder directly under the backup root; ids like ".." or "" cannot escape it. */
    private Path deviceBackupDir(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("deviceId is required");
        }
        Path dir = backupRoot.resolve(sanitizeId(deviceId)).normalize();
        if (!backupRoot.equals(dir.getParent())) {
            throw new IllegalArgumentException("deviceId does not map to a backup folder");
        }
        return dir;
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
            Path deviceDir = deviceBackupDir(driver.getDeviceId());
            if (!Files.exists(deviceDir)) return null;
            Path deviceBackupDir = deviceDir.toRealPath();
            aclGuard.requireSecure(backupRoot.toRealPath(), deviceBackupDir);

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
                    .max(Comparator.comparing(Path::getFileName))
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

        ProcessResult result = runProcess(List.of(
            "powershell.exe", "-NonInteractive", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psCmd));
        return result.output().lines().map(String::trim).filter(l -> !l.isEmpty()).findFirst().orElse("NONE");
    }

    /** Walks without FOLLOW_LINKS and rejects any INF whose real location leaves the device folder. */
    private Path findInfInBackup(Path backupPath, Path realDeviceDir) throws Exception {
        try (var stream = Files.walk(backupPath, 2)) {
            Path inf = stream
                .filter(p -> Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                .filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".inf"))
                .sorted()
                .findFirst()
                .orElse(null);
            if (inf == null) return null;
            Path real = inf.toRealPath();
            if (!isStrictlyInside(real, realDeviceDir)) {
                throw new IllegalArgumentException("INF resolves outside this device's backup directory");
            }
            return real;
        }
    }

    ProcessResult runProcess(List<String> command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) output.append(line).append("\n");
        }
        return new ProcessResult(process.waitFor(), output.toString());
    }

    private String sanitizeId(String deviceId) {
        return deviceId.replaceAll("[\\\\/:*?\"<>|]", "_");
    }

    private String escapeForPowerShell(String input) {
        return input.replace("'", "''").replace("\"", "`\"");
    }
}
