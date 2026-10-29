/*
Added in the soffensive/jwt-reauth fork (2026).
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    https://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.nccgroup.jwtreauth.ui;

import burp.*;
import com.nccgroup.jwtreauth.*;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.nio.file.Path;
import javax.swing.filechooser.FileNameExtensionFilter;

/** Profile configuration uses Burp's own HTTP editor and typed extraction rows. */
public final class SessionProfilesPanel extends JPanel implements IExtensionStateListener {
    private final JWTReauth extension;
    private final SessionProfiles profiles;
    private final DefaultTableModel model = new DefaultTableModel(new String[]{"Profile", "Enabled", "Scope", "Status", "Last success", "Next renewal"}, 0) {
        @Override public boolean isCellEditable(int row, int column) { return false; }
    };
    private final JTable table = new JTable(model);
    private final Timer timer;
    private final JButton saveFile = new JButton("Save profiles...");
    private final JButton loadFile = new JButton("Load profiles...");
    private final JLabel fileStatus = new JLabel("Profile files include requests and token values in plain text.");
    private List<SessionProfile> rows = new ArrayList<>();
    public SessionProfilesPanel(JWTReauth extension) {
        super(new BorderLayout(8, 8)); this.extension = extension; profiles = extension.getSessionProfiles();
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(new JLabel("Each profile renews independently. Select with X-Reauth-Profile: name, or enable automatic scope matching."), BorderLayout.NORTH);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        add(new JScrollPane(table), BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton create = new JButton("New profile"); create.addActionListener(e -> edit(null, null)); actions.add(create);
        JButton edit = new JButton("Edit selected"); edit.addActionListener(e -> { SessionProfile p = selected(); if (p != null) edit(p, null); }); actions.add(edit);
        JButton test = new JButton("Test / renew selected"); test.addActionListener(e -> { SessionProfile p = selected(); if (p != null) profiles.test(p.name); }); actions.add(test);
        JButton remove = new JButton("Delete selected"); remove.addActionListener(e -> { SessionProfile p = selected(); if (p != null) { profiles.remove(p.name); refresh(); } }); actions.add(remove);
        saveFile.addActionListener(e -> saveToFile()); actions.add(saveFile);
        loadFile.addActionListener(e -> loadFromFile()); actions.add(loadFile);
        JPanel footer = new JPanel(new BorderLayout()); footer.add(actions, BorderLayout.NORTH);
        footer.add(fileStatus, BorderLayout.SOUTH); add(footer, BorderLayout.SOUTH);
        timer = new Timer(500, e -> refresh()); timer.start();
        extension.getCallbacks().registerExtensionStateListener(this);
    }
    private SessionProfile selected() {
        int row = table.getSelectedRow(); return row >= 0 && row < rows.size() ? rows.get(row) : null;
    }
    private void refresh() {
        SessionProfile selected = selected(); rows = profiles.list(); model.setRowCount(0);
        for (SessionProfile p : rows) {
            model.addRow(new Object[]{p.name, p.enabled, p.scope.toString(), p.status,
                    p.lastSuccess == null ? "Never" : p.lastSuccess.toString(), p.nextRenewal == null ? "Manual" : p.nextRenewal.toString()});
            if (selected != null && selected.name.equals(p.name)) table.setRowSelectionInterval(model.getRowCount() - 1, model.getRowCount() - 1);
        }
    }
    private JFileChooser chooser() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileFilter(new FileNameExtensionFilter("JWT re-auth profiles (*.json)", "json"));
        return chooser;
    }
    private void fileBusy(boolean busy) { saveFile.setEnabled(!busy); loadFile.setEnabled(!busy); }
    private void fileError(Exception error) {
        Throwable cause = error.getCause() == null ? error : error.getCause();
        JOptionPane.showMessageDialog(this, cause.getMessage(), "Profile file error", JOptionPane.ERROR_MESSAGE);
    }
    private void saveToFile() {
        JFileChooser chooser = chooser(); chooser.setDialogTitle("Save profiles (includes plain-text credentials)");
        chooser.setSelectedFile(new java.io.File("jwt-reauth-profiles.json"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path destination = chooser.getSelectedFile().toPath();
        if (!destination.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".json"))
            destination = destination.resolveSibling(destination.getFileName() + ".json");
        if (java.nio.file.Files.exists(destination) && JOptionPane.showConfirmDialog(this,
                "Replace " + destination.getFileName() + "?", "Save profiles", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        final Path target = destination; List<SessionProfile> saved = profiles.list(); fileBusy(true);
        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() throws Exception { ProfileStore.save(target, saved); return null; }
            @Override protected void done() {
                fileBusy(false);
                try { get(); fileStatus.setText("Saved " + saved.size() + " profile(s) to " + target + " (plain-text credentials)."); }
                catch (Exception ex) { fileError(ex); }
            }
        }.execute();
    }
    private void loadFromFile() {
        JFileChooser chooser = chooser(); chooser.setDialogTitle("Load profiles");
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path source = chooser.getSelectedFile().toPath(); fileBusy(true);
        new SwingWorker<List<SessionProfile>, Void>() {
            @Override protected List<SessionProfile> doInBackground() throws Exception { return ProfileStore.load(source); }
            @Override protected void done() {
                fileBusy(false);
                try {
                    List<SessionProfile> loaded = get();
                    java.util.Set<String> existing = new java.util.HashSet<>(); profiles.list().forEach(p -> existing.add(p.name));
                    List<String> collisions = new ArrayList<>(); loaded.forEach(p -> { if (existing.contains(p.name)) collisions.add(p.name); });
                    if (!collisions.isEmpty() && JOptionPane.showConfirmDialog(SessionProfilesPanel.this,
                            "Replace these existing profiles with the file's settings and values?\n" + String.join(", ", collisions),
                            "Load profiles", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
                    profiles.loadProfiles(loaded); refresh();
                    fileStatus.setText("Loaded " + loaded.size() + " profile(s) from " + source + ". Enabled profiles resume renewal.");
                } catch (Exception ex) { fileError(ex); }
            }
        }.execute();
    }
    public void importRequest(IHttpRequestResponse message) { edit(null, message); }
    private void edit(SessionProfile existing, IHttpRequestResponse imported) {
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Session profile", Dialog.ModalityType.APPLICATION_MODAL);
        JPanel content = new JPanel(new BorderLayout(8, 8)); content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel fields = new JPanel(new GridLayout(0, 2, 6, 6));
        JTextField name = new JTextField(existing == null ? "" : existing.name);
        String importedUrl = imported == null ? "https://example.test/refresh" : extension.getCallbacks().getHelpers().analyzeRequest(imported).getUrl().toString();
        JTextField endpoint = new JTextField(existing == null ? importedUrl : existing.endpoint.toString());
        String defaultScope = imported == null ? "https://example.test/" : origin(extension.getCallbacks().getHelpers().analyzeRequest(imported).getUrl());
        JTextField scope = new JTextField(existing == null ? defaultScope : existing.scope.toString());
        JSpinner interval = new JSpinner(new SpinnerNumberModel(existing == null ? 300 : existing.interval, 5, 86400, 5));
        JComboBox<ReauthHttpClient.Protocol> protocol = new JComboBox<>(ReauthHttpClient.Protocol.values());
        protocol.setSelectedItem(existing == null ? ReauthHttpClient.Protocol.AUTO : existing.protocol);
        JCheckBox enabled = new JCheckBox("Renew and inject automatically", existing != null && existing.enabled);
        JCheckBox auto = new JCheckBox("Select by scope without a marker", existing != null && existing.autoMatch);
        fields.add(new JLabel("Profile name (e.g. alice)")); fields.add(name);
        fields.add(new JLabel("Renewal URL (destination service)")); fields.add(endpoint);
        fields.add(new JLabel("Scope URL (origin and path subtree)")); fields.add(scope);
        fields.add(new JLabel("Renew every (seconds)")); fields.add(interval);
        fields.add(new JLabel("HTTP protocol")); fields.add(protocol);
        fields.add(enabled); fields.add(auto); content.add(fields, BorderLayout.NORTH);
        IMessageEditor requestEditor = extension.getCallbacks().createMessageEditor(null, true);
        String raw = existing == null ? "GET /refresh HTTP/1.1\r\nHost: example.test\r\n\r\n" : existing.request;
        requestEditor.setMessage(imported == null ? extension.getCallbacks().getHelpers().stringToBytes(raw) : imported.getRequest(), true);
        DefaultTableModel rules = new DefaultTableModel(new String[]{"Variable", "Extract from", "Cookie / header / JSON path / regex", "Initial value", "Use in requests", "Destination name", "Value prefix"}, 0);
        if (existing != null) for (SessionProfile.Rule r : existing.rules) rules.addRow(new Object[]{r.variable, r.source, r.selector, r.initial, r.destination, r.target, r.prefix});
        JTable ruleTable = new JTable(rules);
        ruleTable.setRowHeight(25);
        ruleTable.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(new JComboBox<>(SessionProfile.Source.values())));
        ruleTable.getColumnModel().getColumn(4).setCellEditor(new DefaultCellEditor(new JComboBox<>(SessionProfile.Destination.values())));
        JPanel extraction = new JPanel(new BorderLayout(5, 5));
        extraction.add(new JLabel("COOKIE: cookie name · HEADER: header name · JSON: dotted object path · REGEX: first capture group. Use ${variable} in renewal request."), BorderLayout.NORTH);
        extraction.add(new JScrollPane(ruleTable), BorderLayout.CENTER);
        JPanel ruleButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addCookie = new JButton("Add cookie"); addCookie.addActionListener(e -> {
            String cookie = JOptionPane.showInputDialog(dialog, "Cookie name (e.g. session or JSESSIONID):", "session");
            if (cookie != null && !cookie.trim().isEmpty()) {
                cookie = cookie.trim();
                String variable = cookie.replaceAll("[^A-Za-z0-9_]", "_");
                if (!variable.matches("[A-Za-z_].*")) variable = "cookie_" + variable;
                rules.addRow(new Object[]{variable, SessionProfile.Source.COOKIE, cookie, "", SessionProfile.Destination.COOKIE, cookie, ""});
            }
        }); ruleButtons.add(addCookie);
        JButton addHeader = new JButton("Add header / token"); addHeader.addActionListener(e -> rules.addRow(new Object[]{"token", SessionProfile.Source.JSON, "access_token", "", SessionProfile.Destination.HEADER, "Authorization", "Bearer "})); ruleButtons.add(addHeader);
        JButton addVariable = new JButton("Add renewal variable"); addVariable.addActionListener(e -> rules.addRow(new Object[]{"refresh", SessionProfile.Source.JSON, "refresh_token", "", SessionProfile.Destination.VARIABLE, "", ""})); ruleButtons.add(addVariable);
        JButton delete = new JButton("Remove row"); delete.addActionListener(e -> { if (ruleTable.getSelectedRow() >= 0) rules.removeRow(ruleTable.getSelectedRow()); }); ruleButtons.add(delete);
        extraction.add(ruleButtons, BorderLayout.SOUTH);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, requestEditor.getComponent(), extraction); split.setResizeWeight(.55); content.add(split, BorderLayout.CENTER);
        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(new JLabel("Initial values bootstrap renewal. Values are inserted literally. Use Save profiles to persist settings and values. Current tokens and renewal details are visible in the Debugging tab."), BorderLayout.NORTH);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton cancel = new JButton("Cancel"); cancel.addActionListener(e -> dialog.dispose()); buttons.add(cancel);
        for (String action : new String[]{"Save", "Save and test"}) {
            JButton save = new JButton(action); save.addActionListener(e -> {
                try {
                    if (ruleTable.isEditing() && !ruleTable.getCellEditor().stopCellEditing()) return;
                    List<SessionProfile.Rule> definitions = new ArrayList<>();
                    for (int row = 0; row < rules.getRowCount(); row++) definitions.add(new SessionProfile.Rule(
                            cell(rules, row, 0), SessionProfile.Source.valueOf(cell(rules, row, 1)), cell(rules, row, 2), cell(rules, row, 3),
                            SessionProfile.Destination.valueOf(cell(rules, row, 4)), cell(rules, row, 5), cell(rules, row, 6)));
                    SessionProfile profile = new SessionProfile(name.getText().trim(), new URL(endpoint.getText().trim()), new URL(scope.getText().trim()),
                            extension.getCallbacks().getHelpers().bytesToString(requestEditor.getMessage()), ((Number) interval.getValue()).intValue(), definitions, enabled.isSelected(), auto.isSelected(), (ReauthHttpClient.Protocol) protocol.getSelectedItem());
                    profiles.save(profile, existing == null ? null : existing.name);
                    if (action.equals("Save and test") && !profile.enabled) profiles.test(profile.name);
                    refresh(); dialog.dispose();
                } catch (Exception ex) { JOptionPane.showMessageDialog(dialog, ex.getMessage(), "Invalid profile", JOptionPane.ERROR_MESSAGE); }
            }); buttons.add(save);
        }
        bottom.add(buttons, BorderLayout.SOUTH); content.add(bottom, BorderLayout.SOUTH);
        dialog.setContentPane(content); dialog.setSize(1150, 780); dialog.setLocationRelativeTo(this); dialog.setVisible(true);
    }
    private static String cell(DefaultTableModel model, int row, int col) { Object value = model.getValueAt(row, col); return value == null ? "" : value.toString(); }
    private static String origin(URL url) { return url.getProtocol() + "://" + url.getAuthority() + "/"; }
    @Override public void extensionUnloaded() { SwingUtilities.invokeLater(timer::stop); }
}
