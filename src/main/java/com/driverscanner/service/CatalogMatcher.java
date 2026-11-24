package com.driverscanner.service;

import com.driverscanner.model.Driver;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;
import java.util.regex.Pattern;

/** Pure matching of installed drivers against Windows Update Agent driver updates by hardware ID. */
final class CatalogMatcher {

    static final String UPDATE_PREFIX = "UPD";
    static final String CURRENT_MESSAGE = "Driver is current (matches Windows Update catalog)";
    static final String NO_CANDIDATE_MESSAGE = "No newer driver in Windows Update catalog";
    static final String COMPATIBLE_ONLY_NOTE = "matched by compatible ID only - cannot confirm";
    private static final int FIELDS = 10;
    // Class-code IDs (PCI\CC_0280, USB\Class_E0...) name a device type, not a device.
    private static final Pattern CLASS_CODE_ID = Pattern.compile("(?i)\\\\(CC|CLASS)_");
    // Add-on packages that ride on a device's hardware ID but do not replace its function driver.
    private static final Set<String> ADD_ON_CLASSES = Set.of("extension", "softwarecomponent");

    private CatalogMatcher() {}

    /** {@code version} is the update's own driver version when WUA exposes one, else blank. */
    record CatalogUpdate(String hardwareId, LocalDate verDate, String model, String provider,
                         String driverClass, String kb, String updateId, String version, String title) {

        /** Prefers the reported driver version; the title's trailing version is the fallback. */
        String effectiveVersion() {
            return version.isBlank() ? VersionComparator.extractVersion(title) : version;
        }
    }

    /** Outcome for one installed driver: candidate is null when nothing matched. */
    record Match(CatalogUpdate update, boolean compatibleIdOnly, Boolean newer) {}

    /**
     * Parses {@code UPD|hwid|yyyy-MM-dd|model|provider|class|kb|updateId|version|title} lines.
     * Title is last so a stray '|' in it cannot shift the other fields.
     */
    static Map<String, List<CatalogUpdate>> parse(List<String> lines) {
        Map<String, List<CatalogUpdate>> byHwid = new HashMap<>();
        for (String line : lines) {
            if (!line.startsWith(UPDATE_PREFIX + "|")) continue;
            String[] f = line.split("\\|", FIELDS);
            if (f.length < FIELDS) continue;
            String hwid = normalizeId(f[1]);
            if (hwid.isEmpty()) continue;
            CatalogUpdate u = new CatalogUpdate(hwid, parseIsoDate(f[2]), f[3].trim(), f[4].trim(),
                f[5].trim(), f[6].trim(), f[7].trim(), f[8].trim(), f[9].trim());
            byHwid.computeIfAbsent(hwid, k -> new ArrayList<>()).add(u);
        }
        return byHwid;
    }

    static String normalizeId(String id) {
        return id == null ? "" : id.trim().toUpperCase(Locale.ROOT);
    }

    static boolean isClassCodeId(String id) {
        return CLASS_CODE_ID.matcher(id).find();
    }

    /**
     * Hardware-ID matches decide; stale if ANY candidate is newer, reporting the newest such one.
     * Compatible IDs are consulted only when no hardware ID matched, and can never confirm.
     */
    static Match findBest(Driver d, Map<String, List<CatalogUpdate>> catalog) {
        List<CatalogUpdate> byHwid = candidates(d, d.getHardwareIds(), catalog);
        if (byHwid.isEmpty()) {
            CatalogUpdate compat = newest(candidates(d, d.getCompatibleIds(), catalog));
            return new Match(compat, compat != null, null);
        }
        List<CatalogUpdate> newer = new ArrayList<>();
        List<CatalogUpdate> unknown = new ArrayList<>();
        for (CatalogUpdate u : byHwid) {
            Boolean n = isNewer(u, d);
            if (Boolean.TRUE.equals(n)) newer.add(u);
            else if (n == null) unknown.add(u);
        }
        if (!newer.isEmpty()) return new Match(newest(newer), false, true);
        // WU offers it as applicable and not installed, but nothing comparable says it is older.
        if (!unknown.isEmpty()) return new Match(newest(unknown), false, null);
        return new Match(newest(byHwid), false, false);
    }

    private static List<CatalogUpdate> candidates(Driver d, List<String> ids, Map<String, List<CatalogUpdate>> catalog) {
        String ownClass = d.getDeviceClass() == null ? "" : d.getDeviceClass().trim().toLowerCase(Locale.ROOT);
        List<CatalogUpdate> out = new ArrayList<>();
        for (String id : ids) {
            String key = normalizeId(id);
            if (key.isEmpty() || isClassCodeId(key)) continue;
            for (CatalogUpdate u : catalog.getOrDefault(key, List.of())) {
                String cls = u.driverClass().toLowerCase(Locale.ROOT);
                if (ADD_ON_CLASSES.contains(cls) && !cls.equals(ownClass)) continue;
                out.add(u);
            }
        }
        return out;
    }

    /** TRUE/FALSE by version when both parse, else by date; null when neither is comparable. */
    private static Boolean isNewer(CatalogUpdate u, Driver d) {
        String latest = u.effectiveVersion();
        OptionalInt cmp = latest == null ? OptionalInt.empty() : VersionComparator.compare(latest, d.getDriverVersion());
        if (cmp.isPresent()) return cmp.getAsInt() > 0;
        LocalDate installed = parseDriverDate(d.getDriverDate());
        return (u.verDate() == null || installed == null) ? null : u.verDate().isAfter(installed);
    }

    private static CatalogUpdate newest(List<CatalogUpdate> us) {
        CatalogUpdate best = null;
        for (CatalogUpdate u : us) {
            if (best == null || isNewerThan(u, best)) best = u;
        }
        return best;
    }

    private static boolean isNewerThan(CatalogUpdate a, CatalogUpdate b) {
        String va = a.effectiveVersion();
        String vb = b.effectiveVersion();
        OptionalInt cmp = (va == null || vb == null) ? OptionalInt.empty() : VersionComparator.compare(va, vb);
        if (cmp.isPresent()) return cmp.getAsInt() > 0;
        if (a.verDate() == null) return false;
        return b.verDate() == null || a.verDate().isAfter(b.verDate());
    }

    static void apply(Driver d, Match match) {
        CatalogUpdate u = match.update();
        if (u == null) {
            d.setStatus(Driver.Status.UP_TO_DATE);
            d.setStatusMessage(NO_CANDIDATE_MESSAGE);
            return;
        }
        if (match.compatibleIdOnly()) {
            // Too weak to install from: no UpdateID/KB, so the installer cannot act on it.
            d.setStatus(Driver.Status.UNKNOWN);
            d.setStatusMessage("Possible update: " + u.title() + " (" + COMPATIBLE_ONLY_NOTE + ")");
            return;
        }
        if (Boolean.FALSE.equals(match.newer())) {
            d.setStatus(Driver.Status.UP_TO_DATE);
            d.setStatusMessage(CURRENT_MESSAGE);
            return;
        }
        String latest = u.effectiveVersion();
        d.setStatus(Driver.Status.STALE);
        d.setLatestVersion(latest != null ? latest : u.verDate() != null ? u.verDate().toString() : null);
        if (u.verDate() != null) d.setLatestDate(u.verDate().toString());
        if (!u.kb().isBlank()) d.setUpdateKbId(u.kb().split(",")[0].trim());
        if (!u.updateId().isBlank()) d.setUpdateId(u.updateId());
        String msg = "Update available: " + u.title();
        if (match.newer() == null) msg += " (version not comparable)";
        d.setStatusMessage(msg);
    }

    private static LocalDate parseIsoDate(String s) {
        try {
            return LocalDate.parse(s.trim());
        } catch (Exception e) {
            return null;
        }
    }

    /** ISO (yyyy-MM-dd, emitted by the scanner), WMI (yyyyMMdd...) or legacy US-locale (M/d/yyyy ...) dates. */
    static LocalDate parseDriverDate(String raw) {
        if (raw == null || raw.isBlank()) return null;
        if (raw.length() >= 8 && raw.charAt(4) != '-' && raw.charAt(4) != '/') {
            try {
                return LocalDate.parse(raw.substring(0, 8), DateTimeFormatter.BASIC_ISO_DATE);
            } catch (Exception ignored) {}
        }
        if (raw.length() >= 10) {
            try {
                return LocalDate.parse(raw.substring(0, 10), DateTimeFormatter.ISO_LOCAL_DATE);
            } catch (Exception ignored) {}
        }
        try {
            return LocalDate.parse(raw.trim().split("\\s+")[0], DateTimeFormatter.ofPattern("M/d/yyyy"));
        } catch (Exception ignored) {}
        return null;
    }
}
