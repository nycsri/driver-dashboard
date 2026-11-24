package com.driverscanner.service;

import java.nio.file.Path;
import java.util.function.UnaryOperator;

/**
 * Absolute paths to the Windows tools run with admin rights, so a planted icacls.exe/pnputil.exe
 * on PATH or in the working directory is never picked up. The location comes from %SystemRoot%.
 */
final class SystemTools {

    static final String ICACLS = "icacls.exe";
    static final String PNPUTIL = "pnputil.exe";
    static final String POWERSHELL = "WindowsPowerShell\\v1.0\\powershell.exe";

    private SystemTools() {}

    static String path(String tool) {
        return path(tool, System::getenv);
    }

    static String path(String tool, UnaryOperator<String> env) {
        String root = env.apply("SystemRoot");
        if (root == null || root.isBlank()) {
            throw new IllegalStateException("SystemRoot is not set; cannot locate " + tool);
        }
        Path systemRoot = Path.of(root.trim());
        if (!systemRoot.isAbsolute()) {
            throw new IllegalStateException("SystemRoot must be an absolute path, got: " + root);
        }
        return systemRoot.resolve("System32").resolve(tool).toString();
    }
}
