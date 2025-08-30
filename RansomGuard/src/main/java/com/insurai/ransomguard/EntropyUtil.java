package com.insurai.ransomguard;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class EntropyUtil {

    /**
     * Calculate Shannon entropy of a file.
     */
    public static double shannonEntropy(Path path) throws IOException {
        byte[] data = Files.readAllBytes(path);
        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }
        double ent = 0.0;
        int n = data.length;
        for (int count : freq) {
            if (count == 0) continue;
            double p = (double) count / n;
            ent -= p * (Math.log(p) / Math.log(2));
        }
        return ent;
    }

    /**
     * Checks if a file is likely to be encrypted or compressed
     * based on entropy threshold.
     */
    public static boolean isHighEntropy(Path path) {
        try {
            if (!Files.isRegularFile(path) || Files.size(path) == 0) {
                return false;
            }
            double entropy = shannonEntropy(path);
            // 7.5 bits/byte is a common cutoff for suspiciously high entropy
            return entropy >= 7.5;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}
