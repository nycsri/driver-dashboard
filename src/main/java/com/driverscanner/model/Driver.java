package com.driverscanner.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class Driver {

    public enum Status {
        UP_TO_DATE, STALE, UNKNOWN, UPDATING, UPDATE_FAILED
    }

    private String deviceId;         // stable hash of rawDeviceId, used as map key
    private String rawDeviceId;      // original WMI DeviceID (e.g. USBPRINT\...) for WMI lookups
    private String deviceName;
    private String driverVersion;
    private String driverDate;
    private String provider;
    private String deviceClass;
    private Status status;
    private String latestVersion;    // from Windows Update catalog (if found)
    private String latestDate;
    private String updateKbId;       // KB article ID stored at scan time; used by update path
    private String statusMessage;

    // Constructors
    public Driver() {}

    public Driver(String deviceId, String deviceName, String driverVersion,
                  String driverDate, String provider, String deviceClass) {
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.driverVersion = driverVersion;
        this.driverDate = driverDate;
        this.provider = provider;
        this.deviceClass = deviceClass;
        this.status = Status.UNKNOWN;
    }

    // Getters and setters
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }

    public String getRawDeviceId() { return rawDeviceId; }
    public void setRawDeviceId(String rawDeviceId) { this.rawDeviceId = rawDeviceId; }

    public String getDeviceName() { return deviceName; }
    public void setDeviceName(String deviceName) { this.deviceName = deviceName; }

    public String getDriverVersion() { return driverVersion; }
    public void setDriverVersion(String driverVersion) { this.driverVersion = driverVersion; }

    public String getDriverDate() { return driverDate; }
    public void setDriverDate(String driverDate) { this.driverDate = driverDate; }

    public String getProvider() { return provider; }
    public void setProvider(String provider) { this.provider = provider; }

    public String getDeviceClass() { return deviceClass; }
    public void setDeviceClass(String deviceClass) { this.deviceClass = deviceClass; }

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }

    public String getLatestVersion() { return latestVersion; }
    public void setLatestVersion(String latestVersion) { this.latestVersion = latestVersion; }

    public String getLatestDate() { return latestDate; }
    public void setLatestDate(String latestDate) { this.latestDate = latestDate; }

    public String getUpdateKbId() { return updateKbId; }
    public void setUpdateKbId(String updateKbId) { this.updateKbId = updateKbId; }

    public String getStatusMessage() { return statusMessage; }
    public void setStatusMessage(String statusMessage) { this.statusMessage = statusMessage; }
}
