# RansomGuard — Behavioral Ransomware Detection & Containment Prototype

**Intentional minimal prototype exploring real-time behavioral detection, multi-signal fusion, and automated first-response patterns for ransomware-like threats.**

## Purpose & Scope

RansomGuard is a deliberately scoped, single-process prototype built to study real-time filesystem event processing in Java, experiment with combining lightweight behavioral, statistical and signature-based signals, implement safe, controlled simulation of encryption-like behavior, practice automated containment decisions (backup → quarantine → process intervention), and create a visual feedback loop for detection and response validation.

The design consciously favors understandability, modularity and debuggability over breadth of coverage — a common starting point when building and reasoning about endpoint detection mechanisms.

## Architectural Overview

The system follows a layered, event-driven architecture with clear separation of responsibilities.

At the lowest level, the MonitorService uses Java's NIO WatchService to observe a single directory for file creation, modification and deletion events in real time. It runs in a dedicated single-threaded loop and forwards every relevant filesystem event into a processing pipeline.

These events are received by the DetectionEngine, which applies multiple independent detection methods in sequence: Shannon entropy calculation on file content, evaluation against a small set of known ransomware-related file extensions, and — when configured — external YARA rule matching via process execution. Suspicious findings are wrapped into typed ThreatEvent objects carrying severity, message, affected path and optional metadata.

Threat events are propagated to interested listeners, including the user interface and response components. The BackupManager listens for potentially dangerous events and — if the file still exists — creates a timestamped backup copy (with per-file debouncing to avoid redundant copies during rapid changes).

When mass-modification behavior is detected (configurable threshold, currently ≥10 suspicious events in 5 seconds), the system escalates to high-severity alerts and offers automated containment actions. The ProcessManager uses OSHI to enumerate running processes and provides the ability to terminate the currently highest-CPU-utilizing process (used mainly in simulation scenarios). Suspicious files can be atomically moved into a quarantine directory.

The entire flow is orchestrated by the MainApp class, which also hosts the JavaFX-based user interface (threat feed, real-time activity chart, simulation controls, top processes list) and runs the optional encryption/decryption simulation in a separate thread with an explicit stop callback.

This loose coupling via listener interfaces and event objects makes the system easy to extend, debug and reason about while keeping different concerns (monitoring, detection, response, UI, simulation) cleanly separated.

## User Interface

The application features a modern dark-themed dashboard built with JavaFX, providing immediate visibility into system status, real-time activity, threat logs, simulation controls, and response statistics.

![RansomGuard Dashboard](screenshots/ransomguard-dashboard.png)

*Key interface elements:*

- Folder selection and monitoring start/stop controls  
- Real-time encryption events timeline chart  
- Live security log feed with clear button  
- Attack simulation and process termination buttons  
- System status indicators (Monitoring • Simulation • Connection)  
- Quick counters for Encrypted / Decrypted / Backed Up files  
- Tabbed views of Backup Files, Encrypted Files, and Decrypted Files  
- Decrypt and Refresh actions

## Implemented Detection Axes

| Axis                     | Method                              | Rationale / Trade-off                                      |
|--------------------------|-------------------------------------|-------------------------------------------------------------------|
| Content randomness       | Shannon entropy ≥ 7.5 bits/byte     | Fast, stateless signal; effective against bulk encryption         |
| Known patterns           | YARA rule evaluation (external)     | Industry-standard format; allows future rule tuning               |
| File naming convention   | Extension suffix matching           | Low-latency pre-filter; intentionally small list in prototype     |
| Behavioral velocity      | ≥10 suspicious events / 5 seconds   | Simple rate-based trigger; tunable; avoids needing long history   |

## Containment & Response Primitives

- Versioned snapshots — timestamped copies created before suspicious write (60 s debounce per file)
- Atomic quarantine — move to isolated directory on high-confidence events
- User-mediated termination — highest-CPU process kill offered after mass-event trigger (via OSHI + ProcessHandle)
- Simulation kill switch — explicit callback to stop encryption thread when containment is confirmed

## Simulation Environment

A built-in, clearly labeled simulation mode encrypts `.txt` files using fixed-key AES-128-ECB (demonstration only), writes changes that trigger the real detection pipeline, and allows studying the end-to-end flow: monitor → detect → backup → alert → contain. It includes a decrypt function for recovery validation.

## Technology Choices

- Java 17 — records, pattern matching, modern concurrency primitives
- JavaFX 21 — responsive UI with charts and modal dialogs
- OSHI — cross-platform process & resource visibility
- Apache Commons IO — robust file operations
- YARA — de-facto standard for pattern matching (CLI integration stage 1)
- Maven — reproducible builds & dependency management

## Current Scope Boundaries & Next-step Considerations

| Aspect                     | Current Prototype State                          | Architectural / Engineering Trade-off & Next-step Direction |
|----------------------------|--------------------------------------------------|---------------------------------------------------------------------|
| Cryptographic operations   | Fixed key, ECB (simulation only)                 | Isolation of demo crypto; future: per-file keys + KMS-like concept  |
| YARA integration           | External process spawn                           | Fast to prototype; next: evaluate JNA/JNI or pure-Java alternatives |
| Directory scope            | Single folder, non-recursive                     | Simplicity & performance; next: recursive + exclusion patterns      |
| Alerting                   | GUI modal + log feed                             | Immediate feedback; next: async channels (email/webhook/SIEM)       |
| Process attribution        | Highest CPU% (simulation convenience)            | Minimal viable signal; next: parent chain + command-line analysis   |
| Persistence                | In-memory only                                   | Zero state for easy testing; next: lightweight event journal        |
| Tuning & false-positive mgmt | Hardcoded thresholds                             | Focus on mechanism over optimization; next: scoring + whitelisting  |

These boundaries are intentional for a first working version — they keep the codebase small, readable and easy to reason about while still exercising meaningful detection and response patterns.

## Build & Run (Windows-focused development)

**Prerequisites**

- JDK 17+
- Maven
- YARA CLI (`choco install yara` recommended)  
  → adjust `YARA_PATH` in `YaraScanner.java` if necessary

```bash
mvn clean compile
mvn javafx:run
# or
mvn exec:java
