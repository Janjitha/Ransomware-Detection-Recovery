# RansomGuard

Real-time file system monitoring tool with basic ransomware-like behavior detection and response features

## What this project does

RansomGuard is a Java desktop application that:

- Watches a chosen folder for file create/modify events
- Calculates file entropy to detect possible encrypted content
- Runs YARA rules against new/modified files (if YARA is installed)
- Creates timestamped backup copies before suspicious changes
- Has a simple simulation mode that encrypts files in the monitored folder using hardcoded AES
- Shows alerts when many files appear to be encrypted quickly
- Can attempt to kill the most CPU-heavy process when mass encryption is detected (simulation mode)
- Moves suspicious files to a quarantine folder

**Important**: This is an **educational / demonstration project**.  
It is **not** production-grade ransomware protection software.

## Current main detection methods

1. Suspicious file extensions (very limited list)
2. High file entropy (>7.5 bits/byte)
3. Very basic YARA rule matching (one rule looking for ransom note keywords and common extensions)
4. Counting how many suspicious files appear in a short time window (default: 10 in 5 seconds)

## Features that actually work in the current version

- Folder monitoring using Java WatchService
- Shannon entropy calculation on file content
- Very simple YARA integration via external yara64.exe process
- Timestamped backup copies (debounced)
- Move files to quarantine folder
- Graphical interface using JavaFX showing:
  - Threat/log messages
  - Simulation controls
  - Basic activity chart
  - Top CPU processes list
- Simulation mode that:
  - Encrypts .txt files with fixed AES-128-ECB key
  - Decrypts them again
  - Triggers the detection & response logic

## Technologies used

- Java 17
- Maven
- JavaFX 21 (GUI + charts)
- OSHI (system & process information)
- Apache Commons IO & Compress
- Logback (logging – partially configured)
- YARA (external CLI – not embedded)

## Important limitations & warnings

- Uses **very weak** detection logic → many false negatives & false positives
- Simulation uses fixed, hardcoded AES key (1234567890123456)
- Kills highest-CPU process without real validation (dangerous in real use)
- YARA integration depends on external yara64.exe being installed and path being correct
- No digital signature verification
- No network protection
- No memory/process injection detection
- No real decryption key management
- Not suitable for protecting real important data

## How to run (Windows – most tested environment)

### Requirements

- Java 17 JDK
- Maven
- YARA installed (chocolatey: `choco install yara`)
  or manually place yara64.exe and update path in `YaraScanner.java`

### Steps

1. Clone or download the project
2. Open terminal in project folder
3. Build:

```bash
mvn clean compile
