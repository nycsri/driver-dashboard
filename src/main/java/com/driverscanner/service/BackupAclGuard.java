package com.driverscanner.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import static java.nio.file.attribute.AclEntryPermission.*;

/**
 * Verifies that backup folders can only be changed by SYSTEM/Administrators, because rollback
 * hands their contents to an elevated pnputil. Principals are compared by SID
 * (WindowsUserPrincipal equality), never by display name, so the check is locale-independent.
 */
class BackupAclGuard {

    static final String SYSTEM_SID = "S-1-5-18";
    static final String ADMINISTRATORS_SID = "S-1-5-32-544";
    private static final String CREATOR_OWNER_SID = "S-1-3-0";
    private static final String TRUSTED_INSTALLER_SID =
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private static final Set<AclEntryPermission> WRITE = EnumSet.of(
            WRITE_DATA, APPEND_DATA, WRITE_NAMED_ATTRS, DELETE_CHILD, DELETE, WRITE_ACL, WRITE_OWNER);
    // On an ancestor these let the holder rename, replace or re-permission the backup root.
    private static final Set<AclEntryPermission> TAKEOVER = EnumSet.of(DELETE, DELETE_CHILD, WRITE_ACL, WRITE_OWNER);

    record Trust(UserPrincipal system, UserPrincipal administrators,
                 UserPrincipal trustedInstaller, UserPrincipal creatorOwner) {}

    record Acl(UserPrincipal owner, List<AclEntry> entries) {}

    interface AclReader {
        Acl read(Path dir) throws IOException;
    }

    private final Supplier<Trust> trustSource;
    private final AclReader reader;
    private volatile Trust trust;

    BackupAclGuard(Supplier<Trust> trustSource, AclReader reader) {
        this.trustSource = trustSource;
        this.reader = reader;
    }

    static BackupAclGuard windows() {
        return new BackupAclGuard(BackupAclGuard::resolveWellKnown, BackupAclGuard::readNio);
    }

    /**
     * The root and each given folder must be owned by SYSTEM/Administrators and writable by nobody
     * else; the root's ancestors must not let anyone else rename, replace or re-permission it.
     * Pass real paths. Throws InsecureBackupException otherwise.
     */
    void requireSecure(Path realRoot, Path... realDirs) {
        Trust t = trust();
        Set<UserPrincipal> adminOwners = Set.of(t.system(), t.administrators());
        Set<UserPrincipal> ancestorOwners = Set.of(t.system(), t.administrators(), t.trustedInstaller());
        for (Path a = realRoot.getParent(); a != null; a = a.getParent()) {
            check(a, ancestorOwners, TAKEOVER, false, t);
        }
        check(realRoot, adminOwners, WRITE, true, t);
        for (Path d : realDirs) check(d, adminOwners, WRITE, true, t);
    }

    private void check(Path dir, Set<UserPrincipal> owners, Set<AclEntryPermission> forbidden, boolean strict, Trust t) {
        Acl acl;
        try {
            acl = reader.read(dir);
        } catch (IOException e) {
            throw new DriverBackupService.InsecureBackupException("Cannot read the permissions of " + dir + ": " + e.getMessage());
        }
        if (!owners.contains(acl.owner())) {
            throw new DriverBackupService.InsecureBackupException(
                    dir + " is owned by " + acl.owner().getName() + ", not SYSTEM or Administrators");
        }
        Set<UserPrincipal> trusted = Set.of(t.system(), t.administrators(), t.trustedInstaller(), t.creatorOwner());
        for (AclEntry e : acl.entries()) {
            if (e.type() != AclEntryType.ALLOW || trusted.contains(e.principal())) continue;
            boolean inheritOnly = e.flags().contains(AclEntryFlag.INHERIT_ONLY);
            boolean grants = !Collections.disjoint(e.permissions(), forbidden);
            // Inherit-only ACEs keep generic rights that AclEntry cannot decode, so on backup folders they are refused outright.
            if (strict ? inheritOnly || grants : !inheritOnly && grants) {
                throw new DriverBackupService.InsecureBackupException(
                        dir + " can be modified by " + e.principal().getName() + "; only SYSTEM and Administrators may write backup folders");
            }
        }
    }

    private Trust trust() {
        Trust t = trust;
        if (t == null) {
            t = trustSource.get();
            trust = t;
        }
        return t;
    }

    private static Acl readNio(Path dir) throws IOException {
        AclFileAttributeView view = Files.getFileAttributeView(dir, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
        if (view == null) throw new IOException("ACLs are not supported");
        return new Acl(view.getOwner(), view.getAcl());
    }

    /** LookupAccountName rejects SID strings, so the OS translates them to (localised) account names first. */
    private static Trust resolveWellKnown() {
        String script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; '" + String.join("','",
                SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID, CREATOR_OWNER_SID)
                + "' | ForEach-Object { ([Security.Principal.SecurityIdentifier]$_).Translate([Security.Principal.NTAccount]).Value }";
        try {
            Process p = new ProcessBuilder("powershell.exe", "-NonInteractive", "-NoProfile", "-Command", script)
                    .redirectErrorStream(true).start();
            List<String> names;
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                names = r.lines().map(String::trim).filter(l -> !l.isEmpty()).toList();
            }
            if (p.waitFor() != 0 || names.size() != 4) {
                throw new IllegalStateException("unexpected output: " + names);
            }
            UserPrincipalLookupService lookup = FileSystems.getDefault().getUserPrincipalLookupService();
            return new Trust(lookup.lookupPrincipalByName(names.get(0)), lookup.lookupPrincipalByName(names.get(1)),
                    lookup.lookupPrincipalByName(names.get(2)), lookup.lookupPrincipalByName(names.get(3)));
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new DriverBackupService.InsecureBackupException(
                    "Cannot resolve the SYSTEM/Administrators accounts to verify backup folder permissions: " + e.getMessage());
        }
    }
}
