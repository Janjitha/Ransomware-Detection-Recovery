package com.insurai.ransomguard;

import java.nio.file.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;

/**
 * MonitorService watches a directory for file changes,
 * detects mass encryption events and suspicious activity,
 * and provides a popup to kill suspect process and quarantine files.
 *
 * Modified to support stopping an external ransomware simulation thread via callback.
 */
public class MonitorService {

    public enum FileAction { CREATE, MODIFY, DELETE }

    public static class FileEvent {
        private final Path path;
        private final FileAction action;

        public FileEvent(Path path, FileAction action) {
            this.path = path;
            this.action = action;
        }

        public Path getPath() { return path; }
        public FileAction getAction() { return action; }

        @Override
        public String toString() { return action + " -> " + path; }
    }

    public interface Listener {
        void onEvent(ThreatEvent event);
    }

    /**
     * New interface for controlling an external ransomware simulation thread.
     */
    public interface AttackControlListener {
        void stopSimulationThread();
    }

    private final Path dir;
    private final Listener listener;
    private final AttackControlListener attackControlListener;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private volatile boolean running = false;

    private final YaraScanner yaraScanner = new YaraScanner();
    private final BackupManager backupManager = new BackupManager();
    private final ProcessManager processManager = new ProcessManager();

    private static final int ENCRYPTION_THRESHOLD = 10;    // trigger if 10 files quickly encrypted
    private static final long WINDOW_MS = 5000;            // 5-second window
    private final AtomicInteger recentEncryptions = new AtomicInteger(0);
    private long windowStart = System.currentTimeMillis();

    private final List<Path> recentlyEncryptedFiles = new CopyOnWriteArrayList<>();

    /**
     * Constructor adds attackControlListener which can stop the simulation thread outside this class.
     */
    public MonitorService(Path dir, Listener listener, AttackControlListener attackControlListener) {
        this.dir = dir;
        this.listener = listener;
        this.attackControlListener = attackControlListener;
    }

    public void start() {
        running = true;
        executor.submit(() -> {
            try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
                dir.register(
                        watchService,
                        StandardWatchEventKinds.ENTRY_CREATE,
                        StandardWatchEventKinds.ENTRY_MODIFY,
                        StandardWatchEventKinds.ENTRY_DELETE
                );

                while (running) {
                    WatchKey key;
                    try {
                        key = watchService.take();
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }

                    for (WatchEvent<?> ev : key.pollEvents()) {
                        WatchEvent.Kind<?> kind = ev.kind();
                        if (kind == StandardWatchEventKinds.OVERFLOW) continue;

                        Path filename = (Path) ev.context();
                        Path fullPath = dir.resolve(filename);

                        FileAction action;
                        if (kind == StandardWatchEventKinds.ENTRY_CREATE) action = FileAction.CREATE;
                        else if (kind == StandardWatchEventKinds.ENTRY_MODIFY) action = FileAction.MODIFY;
                        else if (kind == StandardWatchEventKinds.ENTRY_DELETE) action = FileAction.DELETE;
                        else continue;

                        safeEmit(ThreatEvent.info("File " + action + ": " + filename, fullPath));

                        if (action != FileAction.DELETE && Files.exists(fullPath) && Files.isRegularFile(fullPath)) {
                            trackEncryptionActivity(fullPath);

                            try {
                                boolean highEntropy = false;
                                try {
                                    highEntropy = EntropyUtil.isHighEntropy(fullPath);
                                } catch (Exception ignored) {}

                                YaraScanner.Result yaraResult = null;
                                try {
                                    yaraResult = yaraScanner.scan(fullPath);
                                } catch (Exception ignored) {}

                                boolean yaraHit = yaraResult != null && yaraResult.matchCount > 0;

                                if (highEntropy || yaraHit) {
                                    recentlyEncryptedFiles.add(fullPath);

                                    // Backup
                                    try {
                                        backupManager.backupIfExists(fullPath);
                                    } catch (Exception bEx) {
                                        bEx.printStackTrace();
                                        safeEmit(ThreatEvent.severe("Backup failed: " + bEx.getMessage(), fullPath));
                                    }

                                    // Severity & Metadata
                                    ThreatEvent.Severity severity;
                                    if (yaraResult != null && yaraResult.matchCount > 2) severity = ThreatEvent.Severity.CRITICAL;
                                    else if (yaraHit) severity = ThreatEvent.Severity.HIGH;
                                    else severity = ThreatEvent.Severity.MEDIUM;

                                    StringBuilder meta = new StringBuilder();
                                    if (highEntropy) {
                                        try { meta.append(String.format("entropy=%.2f", EntropyUtil.shannonEntropy(fullPath))); }
                                        catch (Exception ignored) { meta.append("entropy=high"); }
                                    }
                                    if (yaraHit) {
                                        if (meta.length() > 0) meta.append(" | ");
                                        meta.append("yara=").append(String.join(",", yaraResult.ruleNames));
                                    }

                                    String message = yaraHit ?
                                            "Suspicious file detected (YARA match): " + filename :
                                            "High-entropy file detected: " + filename;

                                    ThreatEvent te;
                                    switch (severity) {
                                        case CRITICAL -> te = ThreatEvent.critical(message, fullPath);
                                        case HIGH -> te = ThreatEvent.high(message, fullPath, meta.toString());
                                        default -> te = ThreatEvent.severe(message, fullPath);
                                    }
                                    safeEmit(te);
                                }
                            } catch (Exception ex) {
                                ex.printStackTrace();
                                safeEmit(ThreatEvent.severe("Detection error: " + ex.getMessage(), fullPath));
                            }
                        }
                    }

                    if (!key.reset()) break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                Path contextPath = (dir != null ? dir : Paths.get("."));
                safeEmit(ThreatEvent.severe("Monitor service error: " + e.getMessage(), contextPath));
            }
        });
    }

    public void stop() {
        running = false;
        executor.shutdownNow();
    }

    private void trackEncryptionActivity(Path filePath) {
        long now = System.currentTimeMillis();

        if (now - windowStart > WINDOW_MS) {
            recentEncryptions.set(0);
            recentlyEncryptedFiles.clear();
            windowStart = now;
        }

        int count = recentEncryptions.incrementAndGet();
        if (count >= ENCRYPTION_THRESHOLD) {
            safeEmit(ThreatEvent.critical("Mass encryption detected! " + count + " files in 5 seconds", filePath));
            showRansomwarePopup();
            recentEncryptions.set(0);
        }
    }

    private void showRansomwarePopup() {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.WARNING);
            alert.setTitle("Ransomware Attack Detected!");
            alert.setHeaderText("Mass encryption activity detected");
            alert.setContentText("Kill the suspect process and quarantine files?");

            ButtonType killBtn = new ButtonType("Kill Process");
            ButtonType ignoreBtn = new ButtonType("Ignore", ButtonBar.ButtonData.CANCEL_CLOSE);

            alert.getButtonTypes().setAll(killBtn, ignoreBtn);

            alert.showAndWait().ifPresent(type -> {
                if (type == killBtn) {
                    if (attackControlListener != null) {
                        attackControlListener.stopSimulationThread();
                    }
                    boolean killed = processManager.killTopSuspect();
                    if (killed) {
                        List<Path> encryptedFilesToQuarantine = List.copyOf(recentlyEncryptedFiles);
                        processManager.quarantineFiles(encryptedFilesToQuarantine);
                        safeEmit(ThreatEvent.high("Suspect process killed, attack stopped. " +
                                encryptedFilesToQuarantine.size() + " files quarantined.", dir, ""));
                    } else {
                        safeEmit(ThreatEvent.severe("Failed to kill suspect process.", dir));
                    }
                    recentlyEncryptedFiles.clear();
                }
            });
        });
    }

    private void safeEmit(ThreatEvent event) {
        try {
            if (listener != null) listener.onEvent(event);
        } catch (Exception ignored) {}
    }
}
