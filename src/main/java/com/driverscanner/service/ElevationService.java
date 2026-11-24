package com.driverscanner.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/** Detects whether the process runs with Administrator rights (needed for pnputil installs). */
@Service
public class ElevationService {

    private static final Logger log = Logger.getLogger(ElevationService.class.getName());

    private static final String CHECK_SCRIPT =
        "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
        + ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)";

    private final int timeoutSeconds;
    private volatile Boolean elevated;

    public ElevationService(@Value("${driver.elevation.check-timeout-seconds:10}") int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
    }

    public boolean isElevated() {
        Boolean cached = elevated;
        if (cached == null) {
            synchronized (this) {
                cached = elevated;
                if (cached == null) {
                    cached = detect();
                    elevated = cached;
                }
            }
        }
        return cached;
    }

    @EventListener(ApplicationReadyEvent.class)
    void warnIfNotElevated() {
        if (!isElevated()) {
            log.warning("Not running as Administrator: driver updates and rollback will fail. "
                + "Restart with run-as-admin.cmd.");
        }
    }

    private boolean detect() {
        try {
            String out = runProcess(List.of("powershell.exe", "-NoProfile", "-NonInteractive",
                "-Command", CHECK_SCRIPT), timeoutSeconds);
            return out != null && out.trim().equalsIgnoreCase("True");
        } catch (Exception e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            log.warning("Elevation check failed, assuming not elevated: " + e.getMessage());
            return false;
        }
    }

    /** Returns stdout, or null on timeout. */
    String runProcess(List<String> command, int timeoutSeconds) throws Exception {
        Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
        p.getOutputStream().close();
        StringBuffer sb = new StringBuffer();
        Thread reader = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append('\n');
            } catch (Exception ignored) {
                // stream closes when the process is killed on timeout
            }
        });
        reader.setDaemon(true);
        reader.start();
        if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            return null;
        }
        reader.join(2000);
        return sb.toString();
    }
}
