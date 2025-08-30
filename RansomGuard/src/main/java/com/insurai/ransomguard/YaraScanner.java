package com.insurai.ransomguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class YaraScanner {

    public static class Result {
        public final int matchCount;
        public final List<String> ruleNames;

        public Result(int matchCount, List<String> ruleNames) {
            this.matchCount = matchCount;
            this.ruleNames = ruleNames;
        }
    }

    /**
     * Scans a file with YARA rules.
     * Requires YARA CLI installed (e.g., via Chocolatey) and available in PATH,
     * or adjust YARA_PATH to the full executable location.
     */
    private static final String YARA_PATH = "C:\\ProgramData\\chocolatey\\lib\\yara\\tools\\yara64.exe";

    public Result scan(Path file) {
        try {
            Path rules = Path.of("rules", "rules.yar");
            List<String> cmd = new ArrayList<>();

            // Use absolute path to avoid "yara not found" errors
            cmd.add(YARA_PATH);

            if (rules.toFile().exists()) {
                cmd.add(rules.toString());
            } else {
                // If no rules, create a trivial rule that never matches
                cmd.add("-e");
                cmd.add("rule no_match { condition: false }");
            }

            cmd.add(file.toString());

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);

            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            List<String> matchedRules = new ArrayList<>();

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    // YARA output: "<rule_name> <file_path>"
                    matchedRules.add(line.split("\\s+")[0]);
                }
            }

            int exitCode = process.waitFor();
            System.out.println("YARA exited with code: " + exitCode);


            // Return match results
            return new Result(matchedRules.size(), matchedRules);

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            // null means scan could not be performed
            return null;
        }
    }
}
