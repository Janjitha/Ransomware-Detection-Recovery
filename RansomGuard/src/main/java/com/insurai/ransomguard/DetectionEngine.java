package com.insurai.ransomguard;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

public class DetectionEngine {

    public interface ThreatListener {
        void onThreat(ThreatEvent event);
    }

    private final ThreatListener listener;
    private final YaraScanner yara = new YaraScanner();
    private final Set<String> suspiciousExt = new HashSet<>();

    public DetectionEngine(ThreatListener listener) {
        this.listener = listener;
        // Common ransomware extensions / markers
        String[] exts = {".locked", ".encrypted", ".enc", ".cry", ".crypt", ".locky", ".ryuk", ".phobos", ".dark"};
        for (String e : exts) suspiciousExt.add(e);
    }

    public void evaluateEvent(MonitorService.FileEvent event) {
        Path p = event.getPath();
        try {
            if (event.getAction() == MonitorService.FileAction.CREATE || event.getAction() == MonitorService.FileAction.MODIFY) {
                // Heuristic 1: suspicious extension
                String name = p.getFileName().toString().toLowerCase();
                for (String ext : suspiciousExt) {
                    if (name.endsWith(ext)) {
                        emit(ThreatEvent.severe("Suspicious extension", p));
                        break;
                    }
                }

                // Heuristic 2: high entropy (possible encryption)
                if (Files.isRegularFile(p) && Files.size(p) > 0 && Files.size(p) < 50 * 1024 * 1024) { // up to 50MB
                    double entropy = EntropyUtil.shannonEntropy(p);
                    if (entropy > 7.5) {
                        emit(ThreatEvent.high("High entropy content", p, String.format("Entropy=%.2f", entropy)));
                    }
                }

                // Signature scan via YARA (best-effort)
                YaraScanner.Result r = yara.scan(p);
                if (r != null && r.matchCount > 0) {
                    emit(ThreatEvent.critical("YARA match: " + r.ruleNames, p));
                }
            }
        } catch (IOException ignored) {
        }
    }

    private void emit(ThreatEvent e) {
        if (listener != null) listener.onThreat(e);
    }
}
