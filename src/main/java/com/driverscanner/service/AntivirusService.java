package com.driverscanner.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Scans files/directories with Windows Defender (MpCmdRun.exe).
 * Requires Windows Defender to be enabled and accessible.
 *
 * MpCmdRun.exe exit codes:
 *   0  = scan completed, no threats found
 *   2  = threats detected (Defender quarantines/removes automatically)
 *        NOTE: exit 2 is also used when the scan itself fails internally
 *        (e.g. hr = 0x80004005 — folder locked by Windows Update).
 *        Check the output text to distinguish a real threat from a tool error.
 *   other = scan could not run (Defender unavailable, permission denied, etc.)
 */
@Service
public class AntivirusService {

    private static final Logger log = LoggerFactory.getLogger(AntivirusService.class);

    private static final String DEFENDER_EXE =
        "C:\\Program Files\\Windows Defender\\MpCmdRun.exe";

/**
     * clean()  = true  → scan ran, no threats
     * clean()  = false → actual threats found (exit 2, no tool error in output)
     * error()  = true  → scan could not complete (tool failure or permission error)
     *
     * Callers must check error() before acting on clean().
     */
    public record ScanResult(boolean clean, boolean error, String message) {
        public static ScanResult clean(String msg)  { return new ScanResult(true,  false, msg); }
        public static ScanResult threat(String msg) { return new ScanResult(false, false, msg); }
        public static ScanResult error(String msg)  { return new ScanResult(false, true,  msg); }
    }

    /**
     * Runs a targeted Windows Defender scan (-ScanType 3) on the given path.
     */
    public ScanResult scanPath(String path) {
        log.info("Antivirus scan starting: {}", path);
        try {
            ProcessBuilder pb = new ProcessBuilder(
                DEFENDER_EXE, "-Scan", "-ScanType", "3", "-File", path
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) output.append(line).append("\n");
            }

            int exitCode = process.waitFor();
            String result = output.toString().trim();

            if (exitCode == 0) {
                log.info("Antivirus scan CLEAN: {}", path);
                return ScanResult.clean("No threats found in: " + path);
            }

            // Exit 2 means threats — but MpCmdRun also exits 2 when it fails internally
            // (e.g. the SoftwareDistribution folder is locked during Windows Update).
            // Detect tool failures by looking for the hr= error pattern in the output.
            if (exitCode == 2 && isToolFailure(result)) {
                log.warn("Antivirus scan could not complete for {} (tool error, not a threat): {}", path, result);
                return ScanResult.error("Scan tool error (not a threat): " + result);
            }

            if (exitCode == 2) {
                log.error("ANTIVIRUS: Threats detected in {}: {}", path, result);
                return ScanResult.threat("THREATS DETECTED in " + path + ": " + result);
            }

            // Any other non-zero exit is a scan infrastructure failure
            log.warn("Antivirus scan could not complete for {} (exit {}): {}", path, exitCode, result);
            return ScanResult.error("Scan could not complete (exit " + exitCode + "): " + result);

        } catch (Exception e) {
            log.error("Antivirus scan failed for '{}'", path, e);
            return ScanResult.error("Scan exception: " + e.getMessage());
        }
    }


    /** Returns true when MpCmdRun output indicates a tool/infrastructure failure
     *  rather than actual malware (hr= COM error codes, CmdTool: Failed, etc.). */
    private boolean isToolFailure(String output) {
        return output.contains("CmdTool: Failed")
            || output.contains("hr = 0x")
            || output.contains("Failed with error")
            || output.contains("could not be opened")
            || output.contains("is not accessible");
    }
}
