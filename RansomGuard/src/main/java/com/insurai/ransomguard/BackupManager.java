package com.insurai.ransomguard;

import org.apache.commons.io.FileUtils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

public class BackupManager {

    private final Path backupRoot;
    // Tracks last backup time for each file
    private final Map<String, Long> lastBackupTime;
    // Set backup interval (in milliseconds), e.g., 1 minute
    private final long backupIntervalMs = 60_000;

    public BackupManager() {
        this.backupRoot = Path.of("backups");
        this.lastBackupTime = new HashMap<>();
        try {
            Files.createDirectories(backupRoot);
        } catch (IOException ignored) {}
    }

    /**
     * Call this method to backup a file if it exists and hasn't been backed up recently.
     */
    public void backupIfExists(Path target) {
        if (Files.exists(target) && Files.isRegularFile(target)) {
            attemptBackup(target);
        }
    }

    // Core debounced backup logic
    private void attemptBackup(Path target) {
        String fileKey = target.toAbsolutePath().toString();
        long now = System.currentTimeMillis();
        Long lastTime = lastBackupTime.get(fileKey);

        // If no backup yet, or enough time has passed, do backup
        if (lastTime == null || (now - lastTime) >= backupIntervalMs) {
            backup(target);
            lastBackupTime.put(fileKey, now);
        }
        // Otherwise, skip backup to avoid duplicates
    }

    /**
     * Actually performs a backup.
     */
    public void backup(Path target) {
        try {
            if (Files.exists(target) && Files.isRegularFile(target)) {
                String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss_SSS"));
                Path dest = backupRoot.resolve(target.getFileName().toString() + "." + ts + ".bak");
                FileUtils.copyFile(target.toFile(), dest.toFile());
            }
        } catch (IOException ignored) {}
    }

    /**
     * Moves the file to quarantine.
     */
    public void quarantine(Path target) {
        try {
            Path q = Path.of("quarantine");
            Files.createDirectories(q);
            Path dest = q.resolve(target.getFileName().toString());
            FileUtils.moveFile(target.toFile(), dest.toFile());
        } catch (IOException ignored) {}
    }
}
