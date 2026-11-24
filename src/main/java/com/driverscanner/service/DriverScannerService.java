package com.driverscanner.service;

import com.driverscanner.model.Driver;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * Queries installed drivers from Windows via WMI using PowerShell.
 * Requires: Windows OS, PowerShell available in PATH, sufficient privileges.
 */
@Service
public class DriverScannerService {

    private static final Logger log = Logger.getLogger(DriverScannerService.class.getName());

    /**
     * PowerShell query to pull driver info from WMI.
     * Fields: DeviceName, DriverVersion, DriverDate, Manufacturer, DeviceClass, DeviceID, HardWareID, CompatID.
     * DriverDate is the UTC calendar date as yyyy-MM-dd: WMI stores midnight UTC, so a local-time or
     * culture-formatted rendering can shift the day or be unparseable.
     * HardWareID/CompatID merge the signed-driver value with the device's full Win32_PnPEntity ID lists
     * (string[]), ';'-joined so ConvertTo-Csv does not emit 'System.String[]'.
     */
    static final String PS_QUERY = """
        $ents = @{};
        Get-CimInstance Win32_PnPEntity | ForEach-Object { if ($_.DeviceID) { $ents[$_.DeviceID] = $_ } };
        Get-CimInstance Win32_PnPSignedDriver |
        Where-Object { $_.DriverVersion -ne $null } |
        Select-Object DeviceName, DriverVersion,
            @{n='DriverDate';e={ if ($_.DriverDate) { $_.DriverDate.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } else { '' } }},
            Manufacturer, DeviceClass, DeviceID,
            @{n='HardWareID';e={ $e = if ($_.DeviceID) { $ents[$_.DeviceID] }; (@($_.HardWareID) + @(if ($e) { $e.HardwareID }) | Where-Object { $_ }) -join ';' }},
            @{n='CompatID';e={ $e = if ($_.DeviceID) { $ents[$_.DeviceID] }; (@($_.CompatID) + @(if ($e) { $e.CompatibleID }) | Where-Object { $_ }) -join ';' }} |
        ConvertTo-Csv -NoTypeInformation
        """;

    public List<Driver> scanInstalledDrivers() throws Exception {
        List<Driver> drivers = new ArrayList<>();

        ProcessBuilder pb = new ProcessBuilder(
            "powershell.exe", "-NonInteractive", "-NoProfile", "-Command", PS_QUERY
        );
        pb.redirectErrorStream(true);
        Process process = pb.start();

        List<String> lines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("PowerShell WMI query failed with exit code: " + exitCode);
        }

        // Parse CSV output (skip header row)
        boolean headerSkipped = false;
        for (String line : lines) {
            if (!headerSkipped) {
                headerSkipped = true;
                continue;
            }
            Driver driver = parseCsvLine(line);
            if (driver != null) {
                drivers.add(driver);
            }
        }

        log.info("Scanned " + drivers.size() + " drivers from WMI.");
        return drivers;
    }

    /**
     * Parses a CSV line from ConvertTo-Csv output.
     * Fields order: DeviceName, DriverVersion, DriverDate, Manufacturer, DeviceClass, DeviceID
     * [, HardWareID, CompatID] - the ID columns are optional so 6-column output still parses.
     */
    static Driver parseCsvLine(String line) {
        try {
            String[] parts = splitCsvLine(line);
            if (parts.length < 6) return null;

            String deviceName  = clean(parts[0]);
            String version     = clean(parts[1]);
            String driverDate  = clean(parts[2]);
            String provider    = clean(parts[3]);
            String deviceClass = clean(parts[4]);
            String deviceId    = clean(parts[5]);

            if (deviceName.isEmpty() || version.isEmpty()) return null;

            String id = deviceId.isEmpty()
                ? UUID.randomUUID().toString()
                : Integer.toHexString(deviceId.hashCode());

            Driver driver = new Driver(id, deviceName, version, driverDate, provider, deviceClass);
            driver.setRawDeviceId(deviceId);
            driver.setHardwareIds(splitIds(parts.length > 6 ? clean(parts[6]) : ""));
            driver.setCompatibleIds(splitIds(parts.length > 7 ? clean(parts[7]) : ""));
            return driver;

        } catch (Exception e) {
            log.warning("Failed to parse driver line: " + line + " | " + e.getMessage());
            return null;
        }
    }

    private static List<String> splitIds(String joined) {
        return Arrays.stream(joined.split(";"))
            .map(CatalogMatcher::normalizeId)
            .filter(id -> !id.isEmpty())
            .distinct()
            .toList();
    }

    private static String clean(String s) {
        return s.replaceAll("^\"|\"$", "").trim();
    }

    /**
     * Simple CSV splitter respecting quoted fields.
     */
    private static String[] splitCsvLine(String line) {
        List<String> result = new ArrayList<>();
        boolean inQuotes = false;
        StringBuilder current = new StringBuilder();

        for (char c : line.toCharArray()) {
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                result.add(current.toString());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        result.add(current.toString());
        return result.toArray(new String[0]);
    }
}
