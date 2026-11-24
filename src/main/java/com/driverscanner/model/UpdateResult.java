package com.driverscanner.model;

public class UpdateResult {
    private boolean success;
    private String message;
    private String deviceId;
    private String backupPath;
    private boolean requiresConfirmation;
    private String backupError;

    public UpdateResult(String deviceId, boolean success, String message) {
        this.deviceId = deviceId;
        this.success = success;
        this.message = message;
    }

    public UpdateResult(String deviceId, boolean success, String message, String backupPath) {
        this(deviceId, success, message);
        this.backupPath = backupPath;
    }

    public static UpdateResult awaitingConfirmation(String deviceId, String backupError) {
        UpdateResult r = new UpdateResult(deviceId, false,
            "Backup failed — explicit approval required to update without a backup.");
        r.requiresConfirmation = true;
        r.backupError = backupError;
        return r;
    }

    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public String getDeviceId() { return deviceId; }
    public String getBackupPath() { return backupPath; }
    public boolean isRequiresConfirmation() { return requiresConfirmation; }
    public String getBackupError() { return backupError; }
}
