package com.insurai.ransomguard;

import java.nio.file.Path;

public class ThreatEvent {

    public enum Severity { INFO, LOW, MEDIUM, HIGH, SEVERE, CRITICAL }

    private final Severity severity;
    private final String message;
    private final Path path;
    private final String meta;

    private ThreatEvent(Severity severity, String message, Path path, String meta) {
        this.severity = severity;
        this.message = message;
        this.path = path;
        this.meta = meta;
    }

    public static ThreatEvent info(String message, Path path) {
        return new ThreatEvent(Severity.INFO, message, path, "");
    }
    public static ThreatEvent high(String message, Path path, String meta) {
        return new ThreatEvent(Severity.HIGH, message, path, meta);
    }
    public static ThreatEvent severe(String message, Path path) {
        return new ThreatEvent(Severity.SEVERE, message, path, "");
    }
    public static ThreatEvent critical(String message, Path path) {
        return new ThreatEvent(Severity.CRITICAL, message, path, "");
    }

    public Severity getSeverity() { return severity; }
    public String getMessage() { return message; }
    public Path getPath() { return path; }
    public String getMeta() { return meta; }

    @Override
    public String toString() {
        return "[" + severity + "] " + message + " | " + path.getFileName() + (meta.isEmpty() ? "" : (" | " + meta));
    }
}
