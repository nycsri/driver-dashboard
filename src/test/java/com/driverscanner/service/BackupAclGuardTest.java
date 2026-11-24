package com.driverscanner.service;

import com.driverscanner.service.DriverBackupService.InsecureBackupException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.nio.file.attribute.AclEntryPermission.*;
import static org.junit.jupiter.api.Assertions.*;

class BackupAclGuardTest {

    record Principal(String getName) implements GroupPrincipal {}

    static final UserPrincipal SYSTEM = new Principal("SYSTEM");
    static final UserPrincipal ADMINS = new Principal("Administrators");
    static final UserPrincipal TRUSTED_INSTALLER = new Principal("TrustedInstaller");
    static final UserPrincipal CREATOR_OWNER = new Principal("CREATOR OWNER");
    static final UserPrincipal USERS = new Principal("Users");
    static final BackupAclGuard.Trust TRUST = new BackupAclGuard.Trust(SYSTEM, ADMINS, TRUSTED_INSTALLER, CREATOR_OWNER);

    static AclEntry allow(UserPrincipal who, Set<AclEntryPermission> perms, AclEntryFlag... flags) {
        AclEntry.Builder b = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(who).setPermissions(perms);
        if (flags.length > 0) b.setFlags(flags);
        return b.build();
    }

    static final Set<AclEntryPermission> FULL = EnumSet.allOf(AclEntryPermission.class);
    static final Set<AclEntryPermission> READ = EnumSet.of(READ_DATA, READ_NAMED_ATTRS, EXECUTE, READ_ATTRIBUTES, READ_ACL, SYNCHRONIZE);
    static final BackupAclGuard.Acl ADMIN_ONLY = new BackupAclGuard.Acl(ADMINS,
            List.of(allow(SYSTEM, FULL), allow(ADMINS, FULL)));

    /** Every path is admin-only unless overridden; for tests whose temp dirs carry the user's real ACL. */
    static BackupAclGuard guard(Map<Path, BackupAclGuard.Acl> overrides) {
        return new BackupAclGuard(() -> TRUST, dir -> overrides.getOrDefault(dir, ADMIN_ONLY));
    }

    static BackupAclGuard trusting() {
        return guard(Map.of());
    }

    private static final Path ROOT = Path.of("C:\\ProgramData\\DriverDashboard\\Backups");
    private static final Path DEVICE = ROOT.resolve("dev-1");

    @ParameterizedTest
    @EnumSource(value = AclEntryPermission.class, names = {"WRITE_DATA", "APPEND_DATA", "DELETE_CHILD", "WRITE_ACL", "DELETE"})
    void rejectsDeviceFolderWritableByUsers(AclEntryPermission perm) {
        var acl = new BackupAclGuard.Acl(ADMINS, List.of(allow(SYSTEM, FULL), allow(ADMINS, FULL),
                allow(USERS, EnumSet.of(READ_DATA, perm))));
        BackupAclGuard g = guard(Map.of(DEVICE, acl));

        assertThrows(InsecureBackupException.class, () -> g.requireSecure(ROOT, DEVICE));
    }

    @Test
    void rejectsRootOwnedByNonAdmin() {
        BackupAclGuard g = guard(Map.of(ROOT, new BackupAclGuard.Acl(USERS, ADMIN_ONLY.entries())));

        assertThrows(InsecureBackupException.class, () -> g.requireSecure(ROOT, DEVICE));
    }

    @Test
    void rejectsInheritableUsersGrantOnRoot() {
        var acl = new BackupAclGuard.Acl(ADMINS, List.of(allow(ADMINS, FULL),
                allow(USERS, EnumSet.noneOf(AclEntryPermission.class), AclEntryFlag.INHERIT_ONLY, AclEntryFlag.DIRECTORY_INHERIT)));

        assertThrows(InsecureBackupException.class, () -> guard(Map.of(ROOT, acl)).requireSecure(ROOT));
    }

    @Test
    void rejectsParentThatLetsUsersReplaceRoot() {
        var parent = new BackupAclGuard.Acl(ADMINS, List.of(allow(ADMINS, FULL), allow(USERS, EnumSet.of(DELETE_CHILD))));

        assertThrows(InsecureBackupException.class, () -> guard(Map.of(ROOT.getParent(), parent)).requireSecure(ROOT));
    }

    @Test
    void acceptsAdminOnlyTreeUnderProgramDataStyleParent() {
        Map<Path, BackupAclGuard.Acl> acls = new HashMap<>();
        // C:\ProgramData: Users may add entries and CREATOR OWNER has an inherit-only grant; neither can replace the root.
        acls.put(Path.of("C:\\ProgramData"), new BackupAclGuard.Acl(SYSTEM, List.of(allow(SYSTEM, FULL), allow(ADMINS, FULL),
                allow(CREATOR_OWNER, EnumSet.noneOf(AclEntryPermission.class), AclEntryFlag.INHERIT_ONLY),
                allow(USERS, READ), allow(USERS, EnumSet.of(WRITE_DATA, APPEND_DATA, WRITE_ATTRIBUTES)))));
        acls.put(Path.of("C:\\"), new BackupAclGuard.Acl(TRUSTED_INSTALLER, List.of(allow(ADMINS, FULL), allow(USERS, READ))));
        acls.put(DEVICE, new BackupAclGuard.Acl(SYSTEM, List.of(allow(SYSTEM, FULL), allow(ADMINS, FULL),
                allow(TRUSTED_INSTALLER, FULL), allow(USERS, READ))));

        assertDoesNotThrow(() -> guard(acls).requireSecure(ROOT, DEVICE));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void realUserOwnedTempFolderIsRejected(@TempDir Path tmp) throws Exception {
        assertThrows(InsecureBackupException.class, () -> BackupAclGuard.windows().requireSecure(tmp.toRealPath()));
    }
}
