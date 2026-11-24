package com.driverscanner.service;

import com.driverscanner.model.Driver;

final class WindowsUpdateLookup {
    private WindowsUpdateLookup() {}
    static boolean isValidUpdateId(String id) { return false; }
    static String escapeForPowerShell(String s) { return s; }
    static String buildInstallScript(Driver d) { return ""; }
}
