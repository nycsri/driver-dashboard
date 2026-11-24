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
            super(root, 7);
        }

        @Override
        ProcessResult runProcess(List<String> command) {
            commands.add(command);
            return new ProcessResult(0, "");
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
        assertEquals("pnputil.exe", cmd.get(0));
        assertEquals("/add-driver", cmd.get(1));
        assertEquals(inf.toRealPath().toString(), cmd.get(2));
    }

    @Test
    void rollbackAcceptsPathInsideOwnDeviceFolder(@TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Path inside = Files.createDirectories(root.resolve("dev-1").resolve("20240101_120000"));
        DriverBackupService real = new DriverBackupService(root, 7);

        assertEquals(inside.toRealPath(), real.resolveBackupPath("dev-1", inside.toString()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "\\DriverDashboard\\Backups", "relative\\Backups"})
    void backupRootMustBeAbsolute(String configured) {
        assertThrows(IllegalStateException.class, () -> DriverBackupService.resolveRoot(configured));
    }
}
