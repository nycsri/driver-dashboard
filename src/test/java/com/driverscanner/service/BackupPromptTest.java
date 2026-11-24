package com.driverscanner.service;

import com.driverscanner.model.Driver;
import com.driverscanner.model.UpdateResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class BackupPromptTest {

    private final DriverBackupService backup = mock(DriverBackupService.class);
    private final List<String> scripts = new ArrayList<>();

    private final DriverUpdateService service = new DriverUpdateService(
            mock(AntivirusService.class), backup, mock(OemUpdateService.class)) {
        @Override
        ProcessOutput runPowerShell(String script) {
            scripts.add(script);
            return new ProcessOutput(0, "NONE");
        }
    };

    private static Driver driver() {
        Driver d = new Driver("dev-1", "Contoso NIC", "1.0", "20240101", "Contoso", "Net");
        d.setUpdateKbId("KB123");
        return d;
    }

    @Test
    void backupFalseSkipsBackupEntirely() throws Exception {
        UpdateResult r = service.triggerUpdate(driver(), false, false);

        verify(backup, never()).backupDriver(any());
        verify(backup, never()).findRecentBackup(any());
        assertFalse(r.isRequiresConfirmation());
        assertNull(r.getBackupPath());
        assertEquals(1, scripts.size(), "update must proceed after explicit skip");
    }

    @Test
    void backupFailureWithoutForceAwaitsConfirmationAndDoesNotUpdate() throws Exception {
        when(backup.findRecentBackup(any())).thenReturn(null);
        when(backup.backupDriver(any())).thenThrow(new Exception("INF not found"));

        UpdateResult r = service.triggerUpdate(driver(), true, false);

        assertTrue(r.isRequiresConfirmation());
        assertEquals("INF not found", r.getBackupError());
        assertTrue(scripts.isEmpty(), "no install may run before the user confirms");
    }

    /** Real path logic with the process seam stubbed, so no test can reach pnputil. */
    private static final class RecordingBackupService extends DriverBackupService {
        final List<List<String>> commands = new ArrayList<>();

        RecordingBackupService(Path root) {
            this(root, BackupAclGuardTest.trusting());
        }

        RecordingBackupService(Path root, BackupAclGuard guard) {
            super(root, 7, guard);
        }

        @Override
        ProcessResult runProcess(List<String> command) {
            commands.add(command);
            return new ProcessResult(0, isExe(command, "powershell.exe") ? "oem42.inf" : "");
        }

        List<List<String>> commands(String exe) {
            return commands.stream().filter(c -> isExe(c, exe)).toList();
        }

        static boolean isExe(List<String> command, String exe) {
            return Path.of(command.get(0)).getFileName().toString().equalsIgnoreCase(exe);
        }
    }

    // OUTSIDE is a temp folder holding an .inf, standing in for e.g. C:\Windows\System32 without touching it.
    @ParameterizedTest
    @ValueSource(strings = {"..\\..\\Windows", "OUTSIDE", "ROOT\\..\\..\\escape", "ROOT", "ROOTsibling\\x",
            "ROOT\\dev-1", "ROOT\\dev-1\\..\\dev-2\\20240101_120000"})
    void rollbackRejectsPathsOutsideDeviceFolder(String raw, @TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Files.createDirectories(root.resolve("dev-1"));
        Files.createFile(Files.createDirectories(root.resolve("dev-2").resolve("20240101_120000")).resolve("x.inf"));
        Files.createDirectories(tmp.resolve("Backupssibling"));
        Path outside = Files.createDirectories(tmp.resolve("outside"));
        Files.createFile(outside.resolve("evil.inf"));
        RecordingBackupService real = new RecordingBackupService(root);
        String path = raw.replace("OUTSIDE", outside.toString()).replace("ROOT", root.toString());

        assertThrows(IllegalArgumentException.class, () -> real.rollbackDriver("dev-1", path));
        assertTrue(real.commands.isEmpty());
    }

    @Test
    void rollbackRejectsBackupInAnotherDevicesFolder(@TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Files.createDirectories(root.resolve("dev-1"));
        Path other = Files.createDirectories(root.resolve("dev-2").resolve("20240101_120000"));
        Files.createFile(other.resolve("oem42.inf"));
        RecordingBackupService real = new RecordingBackupService(root);

        assertThrows(IllegalArgumentException.class, () -> real.rollbackDriver("dev-1", other.toString()));
        assertTrue(real.commands.isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"..", ".", ""})
    void rollbackRejectsDeviceIdThatEscapesBackupRoot(String deviceId, @TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Path inside = Files.createDirectories(root.resolve("dev-1").resolve("20240101_120000"));
        Files.createFile(inside.resolve("oem42.inf"));
        RecordingBackupService real = new RecordingBackupService(root);

        assertThrows(IllegalArgumentException.class, () -> real.rollbackDriver(deviceId, inside.toString()));
        assertTrue(real.commands.isEmpty());
    }

    @Test
    void rollbackInOwnDeviceFolderInstallsUppercaseInf(@TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Path inside = Files.createDirectories(root.resolve("dev-1").resolve("20240101_120000"));
        Path inf = Files.createFile(Files.createDirectories(inside.resolve("net.inf_amd64")).resolve("NET.INF"));
        RecordingBackupService real = new RecordingBackupService(root);

        assertTrue(real.rollbackDriver("dev-1", inside.toString()));

        assertEquals(1, real.commands.size());
        List<String> cmd = real.commands.get(0);
        assertTrue(RecordingBackupService.isExe(cmd, "pnputil.exe"));
        assertEquals("/add-driver", cmd.get(1));
        Path staged = Path.of(cmd.get(2));
        // pnputil gets a private copy, so the validated original cannot be swapped underneath it
        assertNotEquals(inf.toRealPath(), staged);
        assertTrue(staged.startsWith(root.resolve("dev-1").toRealPath()));
        assertTrue(staged.endsWith(Path.of("net.inf_amd64", "NET.INF")));
        assertFalse(Files.exists(staged), "staged copy must be removed after install");
        try (var left = Files.list(root.resolve("dev-1"))) {
            assertEquals(1, left.count(), "only the original backup may remain");
        }
    }

    @Test
    void rollbackRefusesInsecureRootWithoutRunningPnputil(@TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Path inside = Files.createDirectories(root.resolve("dev-1").resolve("20240101_120000"));
        Files.createFile(inside.resolve("oem42.inf"));
        var usersWritable = new BackupAclGuard.Acl(BackupAclGuardTest.ADMINS, List.of(
                BackupAclGuardTest.allow(BackupAclGuardTest.ADMINS, BackupAclGuardTest.FULL),
                BackupAclGuardTest.allow(BackupAclGuardTest.USERS, java.util.EnumSet.of(java.nio.file.attribute.AclEntryPermission.WRITE_DATA))));
        RecordingBackupService real = new RecordingBackupService(root,
                BackupAclGuardTest.guard(java.util.Map.of(root.toRealPath(), usersWritable)));

        assertThrows(DriverBackupService.InsecureBackupException.class, () -> real.rollbackDriver("dev-1", inside.toString()));
        assertTrue(real.commands.isEmpty());
        try (var left = Files.list(root.resolve("dev-1"))) {
            assertEquals(1, left.count(), "no staging folder may be left behind");
        }
    }

    @Test
    void recentBackupInInsecureFolderIsNotReused(@TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Path device = Files.createDirectories(root.resolve("dev-1"));
        Files.createDirectories(device.resolve(java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"))));
        var userOwned = new BackupAclGuard.Acl(BackupAclGuardTest.USERS, BackupAclGuardTest.ADMIN_ONLY.entries());

        assertNotNull(new RecordingBackupService(root).findRecentBackup(driver()));
        assertNull(new RecordingBackupService(root,
                BackupAclGuardTest.guard(java.util.Map.of(device.toRealPath(), userOwned))).findRecentBackup(driver()));
    }

    @Test
    void backupCreatesFoldersWithAdminOnlyAclBeforeExport(@TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("ProgramData").resolve("DriverDashboard").resolve("Backups");
        Files.createDirectories(root.getParent().getParent());
        RecordingBackupService real = new RecordingBackupService(root);

        String backupPath = real.backupDriver(driver());

        List<Path> secured = new ArrayList<>();
        for (List<String> c : real.commands("icacls.exe")) {
            if (c.contains("/inheritance:r")) {
                assertEquals(List.of("/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"),
                        c.subList(2, c.size()));
                secured.add(Path.of(c.get(1)));
            } else {
                assertEquals(List.of("/setowner", "*S-1-5-32-544"), c.subList(2, c.size()));
            }
        }
        assertEquals(List.of(root.getParent(), root, root.resolve("dev-1")), secured);
        assertEquals(6, real.commands("icacls.exe").size());

        int export = real.commands.indexOf(real.commands("pnputil.exe").get(0));
        assertEquals("/export-driver", real.commands.get(export).get(1));
        assertTrue(real.commands.subList(0, export).containsAll(real.commands("icacls.exe")),
                "folders must be locked down before the package is exported into them");
        assertTrue(Path.of(backupPath).startsWith(root.resolve("dev-1")));
    }

    @Test
    void rollbackAcceptsPathInsideOwnDeviceFolder(@TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Path inside = Files.createDirectories(root.resolve("dev-1").resolve("20240101_120000"));
        DriverBackupService real = new DriverBackupService(root, 7, BackupAclGuardTest.trusting());

        assertEquals(inside.toRealPath(), real.resolveBackupPath("dev-1", inside.toString()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\\DriverDashboard\\Backups", "relative\\Backups"})
    void backupRootMustBeAbsolute(String configured) {
        assertThrows(IllegalStateException.class, () -> DriverBackupService.resolveRoot(configured));
    }
}
