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

    @ParameterizedTest
    @ValueSource(strings = {"..\\..\\Windows", "C:\\Windows\\System32", "ROOT\\..\\..\\escape", "ROOT", "ROOTsibling\\x"})
    void rollbackRejectsPathsOutsideBackupRoot(String raw, @TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Files.createDirectories(root);
        Files.createDirectories(tmp.resolve("Backupssibling"));
        DriverBackupService real = new DriverBackupService(root, 7);
        String path = raw.replace("ROOT", root.toString());

        assertThrows(IllegalArgumentException.class, () -> real.rollbackDriver(path));
    }

    @Test
    void rollbackAcceptsPathInsideBackupRoot(@TempDir Path tmp) throws Exception {
        Path root = tmp.resolve("Backups");
        Path inside = Files.createDirectories(root.resolve("dev-1").resolve("20240101_120000"));
        DriverBackupService real = new DriverBackupService(root, 7);

        assertEquals(inside.toRealPath(), real.resolveBackupPath(inside.toString()));
    }
}
