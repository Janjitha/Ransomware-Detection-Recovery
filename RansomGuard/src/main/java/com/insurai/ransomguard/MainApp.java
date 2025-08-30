package com.insurai.ransomguard;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import javafx.animation.*;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.effect.DropShadow;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;
import javafx.util.Duration;

public class MainApp extends Application {
    private static final String AES_KEY = "1234567890123456";
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private MonitorService monitorService;
    private ProcessManager processManager;

    private final ListView<String> threatFeed = new ListView<>();
    private final Label statusLabel = new Label("");
    private final XYChart.Series<Number, Number> activitySeries = new XYChart.Series<>();
    private final AtomicInteger secondTick = new AtomicInteger();

    private final ObservableList<String> encryptedDetails = FXCollections.observableArrayList();
    private final ObservableList<String> decryptedDetails = FXCollections.observableArrayList();
    private final ObservableList<String> backupDetails = FXCollections.observableArrayList();

    private final AtomicInteger totalEncrypted = new AtomicInteger();
    private final AtomicInteger totalDecrypted = new AtomicInteger();
    private final AtomicInteger totalBackups = new AtomicInteger();
    private final Set<String> alreadyDecryptedFiles = new HashSet<>();

    private Thread simulateThread;
    private final AtomicBoolean stopAttack = new AtomicBoolean();
    private Path monitoredPath;

    private static final int STATUS_FADEOUT_SECONDS = 5;

    private final AtomicBoolean isMonitoring = new AtomicBoolean(false);
    private final AtomicBoolean isSimulating = new AtomicBoolean(false);

    private Label valMon;
    private Label valSim;
    private Label valConn;
    private Path quarantineDir;

    @Override
    public void start(Stage stage) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec);

        stage.setTitle("RansomGuard");

        Label title = new Label("RansomGuard");
        title.setStyle("-fx-font-size: 32; -fx-font-weight: bold; -fx-text-fill: #0ffbfd;");
        Label subtitle = new Label("Advanced Ransomware Detection & Response System");
        subtitle.setStyle("-fx-font-size: 13; -fx-font-weight: bold; -fx-text-fill: #05e4ef;");
        VBox titleBar = new VBox(title, subtitle);
        titleBar.setPadding(new Insets(15, 0, 12, 0));
        titleBar.setAlignment(Pos.CENTER);
        titleBar.setStyle("-fx-background-color: #10141a;");

        Label folderLabel = new Label("Monitor Folder:");
        folderLabel.setStyle("-fx-text-fill: #0ffbfd; -fx-font-size: 15; -fx-font-weight: bold;");
        TextField folderPathField = new TextField("./test_folder");
        folderPathField.setEditable(false);
        folderPathField.setStyle("-fx-background-color: #20222b; -fx-text-fill: #e2eef3; -fx-border-radius: 8; -fx-padding: 4 10;");
        Button chooseFolderBtn = styledButton("", "");
        chooseFolderBtn.setPrefWidth(40);
        HBox folderRow = new HBox(8, folderPathField, chooseFolderBtn);
        folderRow.setAlignment(Pos.CENTER_LEFT);

        Button startBtn = colorButton("Start Monitoring", "#35e67d", "#111");
        Button stopBtn = colorButton("Stop Monitoring", "#fb4848", "#fff");
        Button simulateBtn = colorButton("Simulate Attack", "#ffd600", "#2d292b");
        Button killBtn = colorButton("Kill Suspect Process", "#fc8621", "#191717");
        Button viewProcsBtn = colorButton("View Top I/O Procs", "#2fe6ff", "#222");
        VBox buttonsCol = new VBox(14, startBtn, stopBtn, simulateBtn, killBtn, viewProcsBtn);

        Label sysStatusLabel = new Label("System Status");
        sysStatusLabel.setStyle("-fx-text-fill: #0ffbfd; -fx-font-weight: bold;");

        Label lblMon = new Label("Monitoring:");
        lblMon.setStyle("-fx-text-fill: #ffd600; -fx-font-size: 15; -fx-font-weight: bold;");
        Label lblSim = new Label("Attack Simulation:");
        lblSim.setStyle("-fx-text-fill: #ffd600; -fx-font-size: 15; -fx-font-weight: bold;");
        Label lblConn = new Label("Connection:");
        lblConn.setStyle("-fx-text-fill: #0ffbfd; -fx-font-size: 15; -fx-font-weight: bold;");

        valMon = labelStatus("Inactive", "#fb4848");
        valSim = labelStatus("Inactive", "#fb4848");
        valConn = labelStatus("Connected", "#35e67d");

        GridPane statusGrid = new GridPane();
        statusGrid.setVgap(4);
        statusGrid.setHgap(10);
        statusGrid.add(lblMon, 0, 0);
        statusGrid.add(valMon, 1, 0);
        statusGrid.add(lblSim, 0, 1);
        statusGrid.add(valSim, 1, 1);
        statusGrid.add(lblConn, 0, 2);
        statusGrid.add(valConn, 1, 2);
        statusGrid.setStyle("-fx-font-size: 13; -fx-text-fill: #e3eaf0;");
        VBox systemStatusBox = new VBox(5, sysStatusLabel, statusGrid);

        Label encryptedStat = statCard("Encrypted", "", "#2fe6ff", totalEncrypted.get());
        Label decryptedStat = statCard("Decrypted", "", "#89fb69", totalDecrypted.get());
        Label backupStat = statCard("Backed Up", "", "#ffc95b", totalBackups.get());
        VBox statsCards = new VBox(9, encryptedStat, decryptedStat, backupStat);
        statsCards.setPadding(new Insets(12, 0, 0, 0));
        VBox leftPanel = new VBox(14, folderLabel, folderRow, buttonsCol, systemStatusBox, statsCards);
        leftPanel.setPadding(new Insets(24, 21, 24, 21));
        leftPanel.setPrefWidth(275);
        leftPanel.setStyle("-fx-background-color: #181e25; -fx-border-width: 0 1 0 0; -fx-border-color: #15191e;");

        NumberAxis xAxis = new NumberAxis();
        xAxis.setLabel("Time");
        NumberAxis yAxis = new NumberAxis();
        yAxis.setLabel("Encryptions/Second");
        LineChart<Number, Number> chart = new LineChart<>(xAxis, yAxis);
        chart.setPrefHeight(175);
        chart.setLegendVisible(true);
        chart.setCreateSymbols(false);
        chart.setTitle("Encryption Events Timeline");
        chart.setStyle("-fx-background-color: #181c20; -fx-border-radius: 13; -fx-text-fill: #baeaf7;");

        activitySeries.setName("Encryptions/Second");
        chart.getData().add(activitySeries);

        ListView<String> logList = new ListView<>();
        logList.setPrefHeight(165);
        logList.setStyle("-fx-control-inner-background: #232943; -fx-text-fill: #e9feff; -fx-font-family: Consolas; -fx-font-size: 13;");
        logList.setCellFactory(lv -> new ListCell<String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                setText(item);
                if (item != null && item.toLowerCase().contains("error"))
                    setStyle("-fx-text-fill: #fd6060;");
                else if (item != null && item.toLowerCase().contains("info"))
                    setStyle("-fx-text-fill: #2fe6ff;");
                else if (item != null && item.toLowerCase().contains("critical"))
                    setStyle("-fx-text-fill: #ffd35b; -fx-font-weight: bold;");
                else setStyle("-fx-text-fill: #e9feff;");
            }
        });

        Button clearLogBtn = styledButton("", "Clear Log");
        clearLogBtn.setStyle(
                "-fx-background-color: transparent;" +
                "-fx-border-color: #00fff7;" +
                "-fx-text-fill: #00fff7;" +
                "-fx-border-radius: 12;" +
                "-fx-border-width: 2px;" +
                "-fx-font-size: 14;" +
                "-fx-font-weight: bold;" +
                "-fx-font-family: 'Segoe UI Semibold';"
        );
        clearLogBtn.setOnAction(ev -> logList.getItems().clear());

        Label securityLogLabel = new Label("Security Log");
        securityLogLabel.setStyle(
                "-fx-text-fill: #2979FF;" +
                "-fx-font-size: 15;" +
                "-fx-font-family: 'Segoe UI Semibold';" +
                "-fx-font-weight: bold;"
        );
        HBox secLogHeader = new HBox(securityLogLabel, clearLogBtn);
        secLogHeader.setSpacing(10);
        secLogHeader.setAlignment(Pos.CENTER_LEFT);
        secLogHeader.setStyle("-fx-font-size:14; -fx-font-weight:bold; -fx-background-color: #1B2139;");
        VBox secLogBox = new VBox(3, secLogHeader, logList);
        secLogBox.setPadding(new Insets(5, 5, 0, 5));
        secLogBox.setStyle("-fx-background-color: #89088b13; -fx-background-radius: 13;");

        Label encryptedFilesLabel = new Label("Encrypted Files");
        encryptedFilesLabel.setStyle("-fx-text-fill: #2fe6ff; -fx-font-size: 15; -fx-font-weight: bold;");
        ListView<String> encryptedList = new ListView<>(encryptedDetails);
        encryptedList.setPrefHeight(110);
        encryptedList.setStyle("-fx-control-inner-background: #1b1e27; -fx-text-fill: #2fe6ff;");
        VBox encryptedBox = new VBox(6, encryptedFilesLabel, encryptedList);
        encryptedBox.setPadding(new Insets(9));
        encryptedBox.setStyle("-fx-background-color: #20242d; -fx-background-radius: 13;");
        encryptedBox.setPrefWidth(350);

        Label decryptedFilesLabel = new Label("Decrypted Files");
        decryptedFilesLabel.setStyle("-fx-text-fill: #89fb69; -fx-font-size: 15; -fx-font-weight: bold;");
        ListView<String> decryptedList = new ListView<>(decryptedDetails);
        decryptedList.setPrefHeight(110);
        decryptedList.setStyle("-fx-control-inner-background: #1b1e27; -fx-text-fill: #89fb69;");
        VBox decryptedBox = new VBox(6, decryptedFilesLabel, decryptedList);
        decryptedBox.setPadding(new Insets(9));
        decryptedBox.setStyle("-fx-background-color: #20242d; -fx-background-radius: 13;");
        decryptedBox.setPrefWidth(350);

        Label backupFilesLabel = new Label("Backup Files");
        backupFilesLabel.setStyle("-fx-text-fill: #ffc95b; -fx-font-size: 15; -fx-font-weight: bold;");
        ListView<String> backupList = new ListView<>(backupDetails);
        backupList.setPrefHeight(110);
        backupList.setStyle("-fx-control-inner-background: #1b1e27; -fx-text-fill: #ffc95b;");
        VBox backupBox = new VBox(6, backupFilesLabel, backupList);
        backupBox.setPadding(new Insets(9));
        backupBox.setStyle("-fx-background-color: #20242d; -fx-background-radius: 13;");
        backupBox.setPrefWidth(250);

        Button decryptBtn = colorButton("Decrypt", "#35e67d", "#111");
        Button refreshBtn = colorButton("Refresh", "#464b5e", "#ffe599");
        VBox decryptBtnBox = new VBox(12, decryptBtn, refreshBtn);
        decryptBtnBox.setAlignment(Pos.TOP_CENTER);

        HBox filesRow = new HBox(24, backupBox, encryptedBox, decryptedBox, decryptBtnBox);
        filesRow.setAlignment(Pos.CENTER);

        statusLabel.setStyle("-fx-background-color: #03202e; -fx-text-fill: #00fceb; -fx-font-size: 14; -fx-font-weight: bold;" +
                "-fx-border-radius:9; -fx-background-radius:9; -fx-border-color:#00ffff; -fx-border-width:1.4;" +
                "-fx-padding:2 14 2 14;");
        statusLabel.setEffect(new DropShadow(10, Color.web("#02121c")));
        statusLabel.setMinWidth(Region.USE_PREF_SIZE);
        statusLabel.setMaxWidth(320);
        StackPane overlayStatus = new StackPane(statusLabel);
        StackPane.setMargin(statusLabel, new Insets(12, 32, 0, 0));
        overlayStatus.setAlignment(Pos.TOP_RIGHT);
        overlayStatus.setPickOnBounds(false);
        overlayStatus.setMouseTransparent(true);

        VBox mainContent = new VBox(10, chart, secLogBox, filesRow);
        mainContent.setPadding(new Insets(13, 17, 13, 17));
        mainContent.setStyle("-fx-background-color: #181c20; -fx-background-radius: 14;");

        StackPane stack = new StackPane(mainContent, overlayStatus);

        Label footerLabel = new Label("Connected to RansomGuard Dashboard");
        footerLabel.setStyle("-fx-background-color: #10141a; -fx-text-fill: #0ffbfd; -fx-font-size:13; -fx-font-weight: bold; -fx-padding: 6 16;");
        footerLabel.setMaxWidth(Double.MAX_VALUE);

        BorderPane root = new BorderPane();
        root.setTop(titleBar);
        root.setLeft(leftPanel);
        root.setCenter(stack);
        root.setBottom(footerLabel);

        Scene scene = new Scene(root, 1366, 770);
        stage.setScene(scene);
        stage.show();

        fadeIn(titleBar);
        fadeIn(leftPanel);
        fadeIn(mainContent);

        processManager = new ProcessManager();

        chooseFolderBtn.setOnAction(ev -> {
            DirectoryChooser chooser = new DirectoryChooser();
            chooser.setTitle("Select Folder");
            File folder = chooser.showDialog(stage);
            if (folder != null && folder.isDirectory()) {
                monitoredPath = folder.toPath();
                folderPathField.setText(monitoredPath.toString());
                encryptedDetails.clear();
                decryptedDetails.clear();
                backupDetails.clear();
                totalEncrypted.set(0);
                totalDecrypted.set(0);
                totalBackups.set(0);
                alreadyDecryptedFiles.clear();
                updateStats(encryptedStat, decryptedStat, backupStat);
                loadLists(encryptedList, decryptedList);
                setStatus("Selected Folder: " + monitoredPath, "info", true);

                quarantineDir = monitoredPath.resolve("quarantine");
                try {
                    if (!Files.exists(quarantineDir)) {
                        Files.createDirectory(quarantineDir);
                    }
                } catch (IOException ex) {
                    setStatus("Failed to create quarantine: " + ex.getMessage(), "severe", false);
                }
            }
        });

        startBtn.setOnAction(ev -> {
            if (monitoredPath == null) {
                setStatus("Please select a folder first.", "warn", false);
                return;
            }
            if (monitorService != null) monitorService.stop();
            encryptedDetails.clear();
            decryptedDetails.clear();
            backupDetails.clear();
            totalEncrypted.set(0);
            totalDecrypted.set(0);
            totalBackups.set(0);
            alreadyDecryptedFiles.clear();
            updateStats(encryptedStat, decryptedStat, backupStat);

            monitorService = new MonitorService(monitoredPath, event -> {
                String eventStr = event.toString();
                if (isValidFileName(eventStr) && !encryptedDetails.contains(eventStr)) {
                    Platform.runLater(() -> {
                        encryptedDetails.add(eventStr);
                        totalEncrypted.incrementAndGet();
                        updateStats(encryptedStat, decryptedStat, backupStat);
                        threatFeed.getItems().add(eventStr);
                        logList.getItems().add(getTime() + " INFO " + eventStr);
                        setStatus("Monitoring event: " + eventStr, "info", true);
                        if (threatFeed.getItems().size() > 200)
                            threatFeed.getItems().remove(0);
                        activitySeries.getData().add(new XYChart.Data<>(secondTick.incrementAndGet(), totalEncrypted.get()));
                        if (activitySeries.getData().size() > 100)
                            activitySeries.getData().remove(0);
                    });
                    if (totalEncrypted.get() == 10) {
                        boolean killed = processManager.killTopSuspect();
                        Platform.runLater(() -> setStatus(killed ? "Suspect process killed after 10 encryptions." : "Failed to kill suspect process.", killed ? "info" : "severe", true));
                    }
                } else {
                    Platform.runLater(() -> logList.getItems().add(eventStr));
                }
            }, () -> {
                stopAttack.set(true);
                if (simulateThread != null && simulateThread.isAlive()) {
                    simulateThread.interrupt();
                    Platform.runLater(() -> {
                        threatFeed.getItems().add("[SYSTEM] Monitoring stopped.");
                        logList.getItems().add(getTime() + " INFO Monitoring stopped.");
                        setStatus("Monitoring stopped.", "warn", false);
                    });
                }
            });

            monitorService.start();
            isMonitoring.set(true);
            setMonitoringStatus();
            setStatus("Monitoring started.", "info", true);
            logList.getItems().add(getTime() + " INFO Monitoring started.");
        });

        stopBtn.setOnAction(ev -> {
            if (monitorService != null) monitorService.stop();
            isMonitoring.set(false);
            setMonitoringStatus();

            if (simulateThread != null && simulateThread.isAlive()) {
                stopAttack.set(true);
                simulateThread.interrupt();
            }
            isSimulating.set(false);
            setSimulationStatus();

            setStatus("Monitoring stopped.", "warn", false);
            logList.getItems().add(getTime() + " INFO Monitoring stopped.");
        });

        refreshBtn.setOnAction(ev -> {
            encryptedDetails.clear();
            decryptedDetails.clear();
            backupDetails.clear();
            alreadyDecryptedFiles.clear();
            try (var stream = Files.list(monitoredPath)) {
                for (Path path : (Iterable<Path>) stream::iterator) {
                    if (!Files.isRegularFile(path)) continue;
                    String fname = path.getFileName().toString();
                    long size = Files.size(path);
                    if (fname.endsWith(".txt") && !fname.contains("_decrypted") && !fname.endsWith(".bak") && size > 0 && size % 16 == 0) {
                        if (!encryptedDetails.contains(fname)) encryptedDetails.add(fname);
                    } else if ((fname.endsWith(".txt") && size > 0 && size % 16 != 0) || fname.contains("_decrypted")) {
                        if (!decryptedDetails.contains(fname)) decryptedDetails.add(fname);
                    } else if (fname.endsWith(".bak")) {
                        if (!backupDetails.contains(fname)) backupDetails.add(fname);
                    }
                }
            } catch (Exception ex) {
                setStatus("Refresh error: " + ex.getMessage(), "severe", false);
            }
            loadLists(encryptedList, decryptedList);
            updateStats(encryptedStat, decryptedStat, backupStat);
        });

        decryptBtn.setOnAction(ev -> {
            String selected = encryptedList.getSelectionModel().getSelectedItem();
            if (selected == null) {
                setStatus("Select an encrypted file!", "warn", false);
                return;
            }
            String filename = selected.trim();
            Path file = monitoredPath.resolve(filename);
            boolean valid;
            try {
                valid = isValidEncryptedFile(file);
            } catch (IOException ioException) {
                setStatus("Error validating file: " + ioException.getMessage(), "severe", false);
                return;
            }
            if (!valid) {
                setStatus("File not a valid encrypted file.", "warn", false);
                moveToQuarantine(file);
                return;
            }
            try {
                byte[] fileBytes = Files.readAllBytes(file);
                byte[] decryptedBytes = decryptCipher.doFinal(fileBytes);

                // Rename to _decrypted (recommended for UI)
                Path decryptedPath = monitoredPath.resolve(filename.replace(".txt", "_decrypted.txt"));
                Files.write(decryptedPath, decryptedBytes); // Write decrypted file
                Files.delete(file); // Remove encrypted version

                String decryptedName = decryptedPath.getFileName().toString();
                if (alreadyDecryptedFiles.add(decryptedName)) {
                    decryptedDetails.add(decryptedName);
                    totalDecrypted.incrementAndGet();
                    updateStats(encryptedStat, decryptedStat, backupStat);
                }
                setStatus("Decrypted: " + decryptedName, "info", true);
                loadLists(encryptedList, decryptedList);
            } catch (Exception e) {
                setStatus("Unexpected error: " + e.getMessage(), "severe", false);
                moveToQuarantine(file);
            }
        });

        simulateBtn.setOnAction(ev -> {
            isSimulating.set(true);
            setSimulationStatus();
            simulateAttack(encryptedList, decryptedList, logList, encryptedStat, decryptedStat, backupStat);
        });

        killBtn.setOnAction(ev -> {
            stopAttack.set(true);
            if (simulateThread != null && simulateThread.isAlive()) {
                simulateThread.interrupt();
                isSimulating.set(false);
                setSimulationStatus();
                threatFeed.getItems().add("[USER] Simulation stopped.");
                logList.getItems().add(getTime() + " INFO Simulation stopped.");
                setStatus("Simulation stopped.", "info", true);
            } else {
                boolean killed = processManager.killTopSuspect();
                setStatus(killed ? "Suspect process killed (manual)." : "Failed to kill suspect process.", killed ? "info" : "severe", true);
            }
            loadLists(encryptedList, decryptedList);
        });

        viewProcsBtn.setOnAction(ev -> {
            List<String> procs = processManager.topIO();
            logList.getItems().add(getTime() + " INFO Top IO Processes: " + String.join(", ", procs));
        });

        encryptedList.setOnMouseClicked(ev -> {
            if (ev.getClickCount() == 2) {
                String selected = encryptedList.getSelectionModel().getSelectedItem();
                if (selected == null || monitoredPath == null) return;
                Path file = monitoredPath.resolve(selected);
                showFileContentDialog(file, true); // show encrypted raw bytes in hex
            }
        });

        decryptedList.setOnMouseClicked(ev -> {
            if (ev.getClickCount() == 2) {
                String selected = decryptedList.getSelectionModel().getSelectedItem();
                if (selected == null || monitoredPath == null) return;
                Path file = monitoredPath.resolve(selected);
                showFileContentDialog(file, false);
            }
        });

        // example usage, needs proper button reference from your UI:
        Button someButton = new Button("Example");
        someButton.setOnAction(e -> {
            // Handler code...
            loadLists(encryptedList, decryptedList);
        });
    } // end of start()

    private void showFileContentDialog(Path file, boolean showEncrypted) {
        Platform.runLater(() -> {
            String content = "";
            String err = null;
            boolean showingEncrypted = false;
            try {
                byte[] data = Files.readAllBytes(file);

                if (showEncrypted) {
                    StringBuilder sb = new StringBuilder();
                    for (byte b : data) {
                        sb.append(String.format("%02X ", b));
                    }
                    content = sb.toString().trim();
                    showingEncrypted = true;
                } else {
                    content = new String(data).trim();
                    showingEncrypted = false;
                }
            } catch (Exception e) {
                err = "Could not read file: " + e.getMessage();
                content = "(read failed)";
            }
            Alert dialog = new Alert(Alert.AlertType.INFORMATION);
            dialog.setTitle("File Content");
            dialog.setHeaderText(file.getFileName().toString() +
                    (showingEncrypted ? " [encrypted bytes]" : " [decrypted]") +
                    (err != null ? "\n" + err : ""));
            TextArea txt = new TextArea(content);
            txt.setPrefRowCount(14);
            txt.setPrefColumnCount(50);
            txt.setWrapText(true);
            txt.setEditable(false);
            dialog.getDialogPane().setContent(txt);
            dialog.setResizable(true);
            dialog.showAndWait();
        });
    }

    private boolean isValidEncryptedFile(Path file) throws IOException {
        String fname = file.getFileName().toString();
        long size = Files.size(file);
        return fname.endsWith(".txt")
                && !fname.contains("_decrypted")
                && !fname.endsWith(".bak")
                && size > 0
                && size % 16 == 0;
    }

    private boolean isValidFileName(String name) {
        return name.endsWith(".txt")
                && !name.startsWith("[")
                && !name.contains("encrypted at")
                && !name.contains("_decrypted")
                && !name.endsWith(".bak");
    }

    private void setMonitoringStatus() {
        String text = isMonitoring.get() ? "Active" : "Inactive";
        String color = isMonitoring.get() ? "#35e67d" : "#fb4848";
        valMon.setText(text);
        valMon.setStyle("-fx-text-fill: " + color + "; -fx-background-color: transparent; -fx-font-weight: bold; -fx-padding: 2 8; -fx-font-size: 13;");
    }

    private void setSimulationStatus() {
        String text = isSimulating.get() ? "Active" : "Inactive";
        String color = isSimulating.get() ? "#35e67d" : "#fb4848";
        valSim.setText(text);
        valSim.setStyle("-fx-text-fill: " + color + "; -fx-background-color: transparent; -fx-font-weight: bold; -fx-padding: 2 8; -fx-font-size: 13;");
    }

    private void moveToQuarantine(Path file) {
        try {
            if (quarantineDir != null && Files.exists(file)) {
                Files.move(file, quarantineDir.resolve(file.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                Platform.runLater(() -> setStatus("File moved to quarantine: " + file.getFileName(), "warn", false));
            }
        } catch (Exception ex) {
            Platform.runLater(() -> setStatus("Failed to move to quarantine: " + ex.getMessage(), "severe", false));
        }
    }

    private void setStatus(String message, String type, boolean fadeOut) {
        if (!Platform.isFxApplicationThread()) {
            Platform.runLater(() -> setStatus(message, type, fadeOut));
            return;
        }
        statusLabel.setText(message);
        String style;
        switch (type) {
            case "warn" -> style = "-fx-background-color: #292e08; -fx-text-fill: #fcff45; -fx-font-size: 14; -fx-font-weight: bold;" +
                    "-fx-border-radius:9; -fx-background-radius:9; -fx-border-color:#fcee4a; -fx-border-width:1.4;" +
                    "-fx-padding:2 14 2 14;";
            case "severe" -> style = "-fx-background-color: #2e0808; -fx-text-fill: #ff4b71; -fx-font-size: 14; -fx-font-weight: bold;" +
                    "-fx-border-radius:9; -fx-background-radius:9; -fx-border-color:#ff4b71; -fx-border-width:1.4;" +
                    "-fx-padding:2 14 2 14;";
            default -> style = "-fx-background-color: #03202e; -fx-text-fill: #00fceb; -fx-font-size: 14; -fx-font-weight: bold;" +
                    "-fx-border-radius:9; -fx-background-radius:9; -fx-border-color:#00ffff; -fx-border-width:1.4;" +
                    "-fx-padding:2 14 2 14;";
        }
        statusLabel.setStyle(style);
        statusLabel.setEffect(new DropShadow(5, Color.web("#02121c")));
        statusLabel.setOpacity(1.0);
        if (fadeOut && type.equals("info")) {
            Timeline timeline = new Timeline(
                    new KeyFrame(Duration.seconds(STATUS_FADEOUT_SECONDS), evt -> {
                        FadeTransition fade = new FadeTransition(Duration.seconds(1.1), statusLabel);
                        fade.setToValue(0.0);
                        fade.play();
                    })
            );
            timeline.setCycleCount(1);
            timeline.play();
        }
    }

    private void updateStats(Label enc, Label dec, Label bak) {
        enc.setText("Encrypted: " + totalEncrypted.get());
        dec.setText("Decrypted: " + totalDecrypted.get());
        bak.setText("Backed Up: " + totalBackups.get());
    }

    private String getTime() {
        return LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    private Button styledButton(String icon, String text) {
        Button btn = new Button(icon + " " + text);
        btn.setStyle("-fx-background-color: #222; -fx-text-fill: #00ffff; -fx-border-color: #00ffff; -fx-border-radius: 10; -fx-background-radius: 10;");
        btn.setPrefWidth(110);
        btn.setOnMouseEntered(e -> btn.setStyle("-fx-background-color: #00ffff; -fx-text-fill: #000000; -fx-border-color: #33ffee; -fx-border-radius: 12; -fx-background-radius: 12;"));
        btn.setOnMouseExited(e -> btn.setStyle("-fx-background-color: #222; -fx-text-fill: #00ffff; -fx-border-color: #00ffff; -fx-border-radius: 10; -fx-background-radius: 10;"));
        return btn;
    }

    private Button colorButton(String text, String bg, String fg) {
        Button btn = new Button(text);
        btn.setStyle("-fx-background-color: " + bg + "; -fx-text-fill: " + fg + "; -fx-font-weight: bold; -fx-border-radius: 9; -fx-background-radius: 9;");
        btn.setPrefWidth(180);
        btn.setOnMouseEntered(e -> btn.setStyle("-fx-background-color: #04f8f8; -fx-text-fill: #000000; -fx-border-radius: 12; -fx-background-radius: 12;"));
        btn.setOnMouseExited(e -> btn.setStyle("-fx-background-color: " + bg + "; -fx-text-fill: " + fg + "; -fx-font-weight: bold; -fx-border-radius: 9; -fx-background-radius: 9;"));
        return btn;
    }

    private Label labelStatus(String txt, String col) {
        Label lbl = new Label(txt);
        lbl.setStyle("-fx-text-fill: " + col + "; -fx-background-color: transparent; -fx-font-weight: bold; -fx-padding: 2 8; -fx-font-size: 13;");
        return lbl;
    }

    private Label statCard(String type, String icon, String color, int count) {
        Label lbl = new Label(type + ": " + count);
        lbl.setStyle("-fx-background-color: #222733; -fx-text-fill: " + color + "; -fx-font-weight: bold; -fx-border-radius:10; -fx-background-radius:10; -fx-padding:7 13; -fx-font-size:15;");
        lbl.setMinWidth(170);
        lbl.setAlignment(Pos.CENTER_LEFT);
        return lbl;
    }

    private void fadeIn(Region node) {
        FadeTransition ft = new FadeTransition(Duration.seconds(1), node);
        ft.setFromValue(0.05);
        ft.setToValue(1);
        ft.play();
    }

    @Override
    public void stop() throws Exception {
        if (monitorService != null) monitorService.stop();
        isMonitoring.set(false);
        setMonitoringStatus();
        if (simulateThread != null && simulateThread.isAlive()) {
            stopAttack.set(true);
            simulateThread.interrupt();
            isSimulating.set(false);
            setSimulationStatus();
        }
        Platform.exit();
    }

    public static void main(String[] args) {
        launch(args);
    }

    private void simulateAttack(ListView<String> encryptedList, ListView<String> decryptedList, ListView<String> logList,
                                Label encStat, Label decStat, Label bakStat) {
        if (monitoredPath == null) {
            setStatus("Please select a folder first.", "warn", false);
            logList.getItems().add(getTime() + " ERROR No folder selected for simulation.");
            isSimulating.set(false);
            setSimulationStatus();
            return;
        }
        setStatus("Starting simulation...", "info", true);
        threatFeed.getItems().add("[SIM] Attack started");
        logList.getItems().add(getTime() + " INFO Simulated attack started.");
        encryptedDetails.clear();
        backupDetails.clear();
        totalEncrypted.set(0);
        totalBackups.set(0);
        updateStats(encStat, decStat, bakStat);
        alreadyDecryptedFiles.clear();
        stopAttack.set(false);

        simulateThread = new Thread(() -> {
            AtomicInteger sessionCount = new AtomicInteger();
            try {
                List<Path> files = Files.list(monitoredPath).filter(Files::isRegularFile)
                        .filter(p -> !p.getFileName().toString().contains("_decrypted")
                                && !p.getFileName().toString().endsWith(".bak")
                                && !p.getFileName().toString().contains("encrypted at "))
                        .toList();
                for (Path file : files) {
                    if (stopAttack.get() || Thread.interrupted()) break;
                    try {
                        byte[] data = Files.readAllBytes(file);
                        Path backupFile = monitoredPath.resolve(file.getFileName().toString() + ".bak");
                        Files.write(backupFile, data);

                        Platform.runLater(() -> {
                            if (!backupDetails.contains(backupFile.getFileName().toString()))
                                backupDetails.add(backupFile.getFileName().toString());
                            totalBackups.incrementAndGet();
                            updateStats(encStat, decStat, bakStat);
                        });

                        byte[] encryptedData = encryptCipher.doFinal(data);
                        Files.write(file, encryptedData);
                        int count = sessionCount.incrementAndGet();
                        String time = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
                        Platform.runLater(() -> {
                            if (!encryptedDetails.contains(file.getFileName().toString()))
                                encryptedDetails.add(file.getFileName().toString());
                            totalEncrypted.incrementAndGet();
                            updateStats(encStat, decStat, bakStat);
                            setStatus("Simulation running. Total encrypted: " + totalEncrypted.get(), "info", true);
                            threatFeed.getItems().add(file.getFileName().toString() + " encrypted at " + time);
                            logList.getItems().add(getTime() + " INFO " + file.getFileName().toString() + " encrypted at " + time);
                            activitySeries.getData().add(new XYChart.Data<>(secondTick.incrementAndGet(), totalEncrypted.get()));
                            if (activitySeries.getData().size() > 100)
                                activitySeries.getData().remove(0);
                            if (count == 5) {
                                boolean killed = processManager.killTopSuspect();
                                setStatus(killed ? "Suspect process killed after 5 encryptions (sim)." : "Failed to kill suspect process.", killed ? "info" : "severe", true);
                            }
                        });
                        Thread.sleep(300);
                    } catch (Exception e) {
                        Platform.runLater(() -> {
                            threatFeed.getItems().add("[ERROR] " + e.getMessage());
                            logList.getItems().add(getTime() + " ERROR " + e.getMessage());
                        });
                        moveToQuarantine(file);
                    }
                }
                Platform.runLater(() -> {
                    setStatus("Simulation completed. Total encrypted: " + totalEncrypted.get(), "info", true);
                    logList.getItems().add(getTime() + " INFO Simulation completed. Total encrypted: " + totalEncrypted.get());
                    updateStats(encStat, decStat, bakStat);
                    loadLists(encryptedList, decryptedList);
                    isSimulating.set(false);
                    setSimulationStatus();
                });
            } catch (Exception e) {
                Platform.runLater(() -> {
                    setStatus("Simulation error: " + e.getMessage(), "severe", false);
                    isSimulating.set(false);
                    setSimulationStatus();
                });
            }
        });
        simulateThread.start();
    }

    private void loadLists(ListView<String> encryptedList, ListView<String> decryptedList) {
        if (monitoredPath == null) return;
        Platform.runLater(() -> {
            if (encryptedList != null) encryptedList.getItems().clear();
            if (decryptedList != null) decryptedList.getItems().clear();
            try {
                try (var stream = Files.list(monitoredPath)) {
                    for (Path path : (Iterable<Path>) stream::iterator) {
                        if (Files.isRegularFile(path)) {
                            String fname = path.getFileName().toString();
                            long size = Files.size(path);
                            if (encryptedList != null && fname.endsWith(".txt") && !fname.contains("_decrypted") && !fname.endsWith(".bak")
                                    && size % 16 == 0 && size > 0) {
                                if (!encryptedList.getItems().contains(fname))
                                    encryptedList.getItems().add(fname);
                            } else if (decryptedList != null && ((fname.endsWith(".txt") && size > 0 && size % 16 != 0)
                                    || fname.contains("_decrypted"))) {
                                if (!decryptedList.getItems().contains(fname))
                                    decryptedList.getItems().add(fname);
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        });
    }
}
