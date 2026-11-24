package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Runs a full driver scan once per day on the configured schedule, then
 * scans the Windows Update download cache with Windows Defender.
 *
 * Default schedule: 2:00 AM every day.
 * Override via application.properties: driver.scan.schedule=<cron-expression>
 */
@Service
public class ScheduledDriverScanService {

    private static final Logger log = LoggerFactory.getLogger(ScheduledDriverScanService.class);

    @Autowired private DriverOrchestrationService orchestrationService;

    @Scheduled(cron = "${driver.scan.schedule:0 0 2 * * ?}")
    public void runDailyScan() {
        log.info("=== Daily driver scan started at {} ===", LocalDateTime.now());
        try {
            List<Driver> drivers = orchestrationService.runFullScan();

            long total   = drivers.size();
            long stale   = drivers.stream().filter(d -> d.getStatus() == Driver.Status.STALE).count();
            long unknown = drivers.stream().filter(d -> d.getStatus() == Driver.Status.UNKNOWN).count();

            log.info("Scan complete — total: {}, stale: {}, unknown: {}", total, stale, unknown);
        } catch (Exception e) {
            log.error("Daily driver scan failed", e);
        }
        log.info("=== Daily driver scan finished at {} ===", LocalDateTime.now());
    }
}
