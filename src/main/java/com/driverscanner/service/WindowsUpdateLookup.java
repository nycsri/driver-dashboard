package com.driverscanner.service;

import com.driverscanner.model.Driver;

import java.util.regex.Pattern;

/** Builds the PSWindowsUpdate install script; every value placed on the command line is validated or escaped here. */
final class WindowsUpdateLookup {

    private static final Pattern UPDATE_ID = Pattern.compile(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern KB_ID = Pattern.compile("(?:KB)?\\d{1,10}", Pattern.CASE_INSENSITIVE);
    // PowerShell treats ' and the curly single quotes U+2018..U+201B as single-quote delimiters.
    private static final Pattern SINGLE_QUOTES = Pattern.compile("(['‘’‚‛])");

    private static final String INSTALL_BODY = """
        if ($target) {
            $r = $target | Install-WindowsUpdate -AcceptAll -AutoReboot:$false -IgnoreReboot -ErrorAction SilentlyContinue;
            if ($r) { Write-Output ('SUCCESS: ' + ($r | Select-Object -ExpandProperty Title)) }
            else    { Write-Output 'NONE' }
        } else {
            Write-Output 'NONE'
        }
        """;

    private WindowsUpdateLookup() {}

    static boolean isValidUpdateId(String id) {
        return id != null && UPDATE_ID.matcher(id).matches();
    }

    /** For use inside single-quoted PowerShell strings only: doubles each single-quote character. */
    static String escapeForPowerShell(String input) {
        return input == null ? "" : SINGLE_QUOTES.matcher(input).replaceAll("$1$1");
    }

    /** Lookup order: UpdateID (exact), then KB article, then device-name-in-title regex. */
    static String targetLookup(Driver driver) {
        String updateId = driver.getUpdateId();
        if (isValidUpdateId(updateId)) {
            return "$target = Get-WindowsUpdate -UpdateID '" + updateId
                + "' -ErrorAction SilentlyContinue | Select-Object -First 1;";
        }
        String kbId = driver.getUpdateKbId() == null ? null : driver.getUpdateKbId().trim();
        if (kbId != null && KB_ID.matcher(kbId).matches()) {
            return "$target = Get-WindowsUpdate -KBArticleID '" + kbId
                + "' -ErrorAction SilentlyContinue | Select-Object -First 1;";
        }
        return "$all = Get-WindowsUpdate -Category 'Drivers' -ErrorAction SilentlyContinue;\n"
            + "$pat = [Regex]::Escape('" + escapeForPowerShell(driver.getDeviceName()) + "');\n"
            + "$target = $all | Where-Object { $_.Title -match $pat } | Select-Object -First 1;";
    }

    static String buildInstallScript(Driver driver) {
        return "Import-Module PSWindowsUpdate -ErrorAction Stop;\n" + targetLookup(driver) + "\n" + INSTALL_BODY;
    }
}
