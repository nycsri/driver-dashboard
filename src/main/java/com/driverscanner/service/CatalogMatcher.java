package com.driverscanner.service;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

final class CatalogMatcher {
    private CatalogMatcher() {}
    record CatalogUpdate(String hardwareId, LocalDate verDate, String model, String provider,
                         String driverClass, String kb, String updateId, String title) {}
    static Map<String, List<CatalogUpdate>> parse(List<String> lines) { return Map.of(); }
}
