package com.driverscanner.service;

import com.driverscanner.model.Driver;
import com.driverscanner.service.DriverBackupService.InsecureBackupException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static java.nio.file.attribute.AclEntryPermission.WRITE_DATA;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** A junction or a non-admin entry anywhere on the way to pnputil must stop the rollback before it runs. */
@EnabledOnOs(OS.WINDOWS)
class BackupJunctionTest {

    private static final class Recording extends DriverBackupService {
        final List<List<String>> commands = new ArrayList<>();
        final int pnputilExit;

        Recording(Path root, BackupAclGuard guard, int pnputilExit) {
            super(root, 7, guard);
            this.pnputilExit = pnputilExit;
        }

        Recording(Path root) {
            this(root, BackupAclGuardTest.trusting(), 0);
        }

        @Override
        ProcessResult runProcess(List<String> command) {
            commands.add(command);
            String exe = Path.of(command.get(0)).getFileName().toString();
            if (exe.equalsIgnoreCase("powershell.exe")) return new ProcessResult(0, "oem42.inf");
            return new ProcessResult(exe.equalsIgnoreCase("pnputil.exe") ? pnputilExit : 0, "");
        }

        boolean ran(String exe) {
            return commands.stream().anyMatch(c -> Path.of(c.get(0)).getFileName().toString().equalsIgnoreCase(exe));
        }
    }

    private static void junction(Path link, Path target) throws Exception {
        Process p = new ProcessBuilder("cmd.exe", "/c", "mklink", "/J", link.toString(), target.toString())
                .redirectErrorStream(true).start();
        p.getInputStream().readAllBytes();
        assumeTrue(p.waitFor() == 0 && Files.exists(link), "cannot create junctions here");
    }

    private static Path backupIn(Path deviceDir) throws Exception {
        Path ts = Files.createDirectories(deviceDir.resolve("20240101_120000"));
        Files.createFile(ts.resolve("oem42.inf"));
        return ts;
    }

    private static Driver driver() {
        return new Driver("dev-1", "Contoso NIC", "1.0", "20240101", "Contoso", "Net");
    }

    private static long entries(Path dir) throws Exception {
        try (var s = Files.list(dir)) {
            return s.count();
        }
    }

    @Test
    void rollbackRefusesJunctionedBackupRoot(@TempDir Path tmp) throws Exception {
        Path target = Files.createDirectories(tmp.resolve("attacker"));
        backupIn(target.resolve("dev-1"));
        Path root = tmp.resolve("Backups");
        junction(root, target);
        Recording svc = new Recording(root);

        assertThrows(InsecureBackupException.class,
                () -> svc.rollbackDriver("dev-1", root.resolve("dev-1").resolve("20240101_120000").toString()));
        assertFalse(svc.ran("pnputil.exe"));
    }

    @Test
    void backupRefusesJunctionedBackupRootBeforeCreatingAnythingInIt(@TempDir Path tmp) throws Exception {
        Path target = Files.createDirectories(tmp.resolve("attacker"));
        Path root = tmp.resolve("Backups");
        junction(root, target);
        Recording svc = new Recording(root);

        assertThrows(InsecureBackupException.class, () -> svc.backupDriver(driver()));
        assertFalse(svc.ran("pnputil.exe"));
        assertEquals(0, entries(target), "nothing may be created through the junction");
    }

    // dev-2 stays under the real root, so a parent-only check would accept it and install dev-2's package for dev-1
    @ParameterizedTest
    @ValueSource(strings = {"sibling", "outside"})
    void rollbackRefusesDeviceFolderThatResolvesElsewhere(String where, @TempDir Path tmp) throws Exception {
        Path root = Files.createDirectories(tmp.resolve("Backups"));
        Path elsewhere = where.equals("sibling") ? root.resolve("dev-2") : tmp.resolve("outside").resolve("dev-1");
        backupIn(elsewhere);
        junction(root.resolve("dev-1"), elsewhere);
        Recording svc = new Recording(root);

        assertThrows(InsecureBackupException.class,
                () -> svc.rollbackDriver("dev-1", root.resolve("dev-1").resolve("20240101_120000").toString()));
        assertFalse(svc.ran("pnputil.exe"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"sub", "sub\\oem42.inf"})
    void rollbackRefusesBackupContentWritableByNonAdmins(String planted, @TempDir Path tmp) throws Exception {
        Path root = Files.createDirectories(tmp.resolve("Backups"));
        Path ts = backupIn(root.resolve("dev-1"));
        Files.createFile(Files.createDirectories(ts.resolve("sub")).resolve("oem42.inf"));
        var usersWritable = new BackupAclGuard.Acl(BackupAclGuardTest.ADMINS, List.of(
                BackupAclGuardTest.allow(BackupAclGuardTest.ADMINS, BackupAclGuardTest.FULL),
                BackupAclGuardTest.allow(BackupAclGuardTest.USERS, EnumSet.of(WRITE_DATA))));
        var usersOwned = new BackupAclGuard.Acl(BackupAclGuardTest.USERS, BackupAclGuardTest.ADMIN_ONLY.entries());
        Path p = ts.resolve(planted).toRealPath();
        Recording svc = new Recording(root, BackupAclGuardTest.guard(
                Map.of(p, planted.endsWith(".inf") ? usersWritable : usersOwned)), 0);

        assertThrows(InsecureBackupException.class, () -> svc.rollbackDriver("dev-1", ts.toString()));
        assertFalse(svc.ran("pnputil.exe"));
        assertEquals(1, entries(root.resolve("dev-1")), "staging must be removed");
    }

    @Test
    void stagingIsRemovedWhenPnputilFails(@TempDir Path tmp) throws Exception {
        Path root = Files.createDirectories(tmp.resolve("Backups"));
        Path ts = backupIn(root.resolve("dev-1"));
        Recording svc = new Recording(root, BackupAclGuardTest.trusting(), 1);

        assertThrows(Exception.class, () -> svc.rollbackDriver("dev-1", ts.toString()));
        assertTrue(svc.ran("pnputil.exe"));
        assertEquals(1, entries(root.resolve("dev-1")), "staging must be removed");
    }

    @Test
    void toolsRunFromAbsoluteSystem32Paths(@TempDir Path tmp) throws Exception {
        Path root = Files.createDirectories(tmp.resolve("Backups"));
        Path ts = backupIn(root.resolve("dev-1"));
        Recording svc = new Recording(root);

        svc.backupDriver(driver());
        svc.rollbackDriver("dev-1", ts.toString());

        Path system32 = Path.of(System.getenv("SystemRoot"), "System32");
        assertFalse(svc.commands.isEmpty());
        for (List<String> c : svc.commands) {
            Path exe = Path.of(c.get(0));
            assertTrue(exe.isAbsolute() && exe.startsWith(system32), "not absolute System32: " + c.get(0));
        }
    }
}
