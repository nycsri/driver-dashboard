package com.driverscanner.service;

import com.driverscanner.model.Driver;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

/** Pure matching of installed drivers against Windows Update Agent driver updates by hardware ID. */
final class CatalogMatcher {

    static final String UPDATE_PREFIX = "UPD";
    static final String CURRENT_MESSAGE = "Driver is current (matches Windows Update catalog)";
    static final String NO_CANDIDATE_MESSAGE = "No newer driver in Windows Update catalog";
    private static final int FIELDS = 9;

    private CatalogMatcher() {}

    record CatalogUpdate(String hardwareId, LocalDate verDate, String model, String provider,
                         String driverClass, String kb, String updateId, String title) {}

    record Match(CatalogUpdate update, boolean compatibleIdOnly) {}

    /**
     * Parses {@code UPD|hwid|yyyy-MM-dd|model|provider|class|kb|updateId|title} lines.
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
                f[5].trim(), f[6].trim(), f[7].trim(), f[8].trim());
            byHwid.computeIfAbsent(hwid, k -> new ArrayList<>()).add(u);
        }
        return byHwid;
    }

    static String normalizeId(String id) {
        return id == null ? "" : id.trim().toUpperCase(Locale.ROOT);
    }

    /** Hardware-ID matches win; compatible IDs are consulted only when no hardware ID matched. */
    static Optional<Match> findBest(Driver d, Map<String, List<CatalogUpdate>> catalog) {
        Optional<CatalogUpdate> byHwid = newest(d.getHardwareIds(), catalog);
        if (byHwid.isPresent()) return Optional.of(new Match(byHwid.get(), false));
        return newest(d.getCompatibleIds(), catalog).map(u -> new Match(u, true));
    }

    private static Optional<CatalogUpdate> newest(List<String> ids, Map<String, List<CatalogUpdate>> catalog) {
        List<CatalogUpdate> candidates = new ArrayList<>();
        for (String id : ids) candidates.addAll(catalog.getOrDefault(normalizeId(id), List.of()));
        return candidates.stream().max(Comparator.comparing(CatalogUpdate::verDate,
            Comparator.nullsFirst(Comparator.naturalOrder())));
    }

    static void apply(Driver d, Optional<Match> match) {
        if (match.isEmpty()) {
            d.setStatus(Driver.Status.UP_TO_DATE);
            d.setStatusMessage(NO_CANDIDATE_MESSAGE);
            return;
        }
        CatalogUpdate u = match.get().update();
        String latest = VersionComparator.extractVersion(u.title());
        OptionalInt cmp = latest == null ? OptionalInt.empty() : VersionComparator.compare(latest, d.getDriverVersion());

        Boolean newer;
        if (cmp.isPresent()) {
            newer = cmp.getAsInt() > 0;
        } else {
            LocalDate installed = parseDriverDate(d.getDriverDate());
            newer = (u.verDate() == null || installed == null) ? null : u.verDate().isAfter(installed);
        }

        if (Boolean.FALSE.equals(newer)) {
            d.setStatus(Driver.Status.UP_TO_DATE);
            d.setStatusMessage(CURRENT_MESSAGE);
            return;
        }
        d.setStatus(Driver.Status.STALE);
        d.setLatestVersion(latest != null ? latest : u.verDate() != null ? u.verDate().toString() : null);
        if (u.verDate() != null) d.setLatestDate(u.verDate().toString());
        if (!u.kb().isBlank()) d.setUpdateKbId(u.kb().split(",")[0].trim());
        if (!u.updateId().isBlank()) d.setUpdateId(u.updateId());
        String msg = "Update available: " + u.title();
        // WU offered it for this device, but neither version nor date could be compared.
        if (newer == null) msg += " (version not comparable)";
        if (match.get().compatibleIdOnly()) msg += " (matched by compatible ID)";
        d.setStatusMessage(msg);
    }

    private static LocalDate parseIsoDate(String s) {
        try {
            return LocalDate.parse(s.trim());
        } catch (Exception e) {
            return null;
        }
    }

    /** WMI (yyyyMMdd...), ISO (yyyy-MM-dd...) or US-locale (M/d/yyyy ...) driver dates. */
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
