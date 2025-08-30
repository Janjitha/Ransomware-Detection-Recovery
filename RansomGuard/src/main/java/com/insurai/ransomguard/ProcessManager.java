package com.insurai.ransomguard;

import oshi.SystemInfo;
import oshi.software.os.OSProcess;
import oshi.software.os.OperatingSystem;
import org.apache.commons.io.FileUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Manages system processes and quarantine operations.
 */
public class ProcessManager {

    private final SystemInfo si = new SystemInfo();
    private final OperatingSystem os = si.getOperatingSystem();

    /**
     * Returns a list of top 10 processes by CPU utilization, approximating IO-heavy or suspicious processes.
     */
    public List<String> topIO() {
        List<OSProcess> procs = os.getProcesses(
                null,
                OperatingSystem.ProcessSorting.CPU_DESC,
                10
        );

        List<String> out = new java.util.ArrayList<>();
        for (OSProcess p : procs) {
            out.add(String.format(
                    "PID %d | %s | CPU %.1f%% | Mem %.1f MB",
                    p.getProcessID(),
                    p.getName(),
                    100.0 * p.getProcessCpuLoadCumulative(),
                    p.getResidentSetSize() / (1024.0 * 1024)
            ));
        }
        return out;
    }

    /**
     * Attempts to kill the process consuming most CPU resources.
     * @return true if process was successfully terminated or forcibly killed, false otherwise.
     */
    public boolean killTopSuspect() {
        List<OSProcess> procs = os.getProcesses(
                null,
                OperatingSystem.ProcessSorting.CPU_DESC,
                1
        );

        if (procs.isEmpty()) return false;

        OSProcess top = procs.get(0);
        long pid = top.getProcessID();

        return ProcessHandle.of(pid)
                .map(ph -> {
                    boolean soft = ph.destroy();
                    if (!soft) {
                        try {
                            return ph.destroyForcibly();
                        } catch (Exception e) {
                            return false;
                        }
                    }
                    return true;
                })
                .orElse(false);
    }

    /**
     * Moves a single file to the quarantine folder.
     * @param target the file to move to quarantine
     */
    public void quarantine(Path target) {
        try {
            if (Files.exists(target) && Files.isRegularFile(target)) {
                Path q = Path.of("quarantine");
                Files.createDirectories(q);
                Path dest = q.resolve(target.getFileName());
                // Use moveFile to ensure atomic move
                FileUtils.moveFile(target.toFile(), dest.toFile());
            }
        } catch (IOException ignored) {
            // Log or handle exception if needed
        }
    }

    /**
     * Moves multiple files to the quarantine folder.
     * @param files list of files to be quarantined
     */
    public void quarantineFiles(List<Path> files) {
        for (Path file : files) {
            quarantine(file);
        }
    }
}
