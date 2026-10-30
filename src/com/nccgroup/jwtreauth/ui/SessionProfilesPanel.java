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
    private boolean refreshing;
    private final DefaultTableModel model = new DefaultTableModel(new String[]{"Profile", "Active", "Match by", "Applies to", "Status", "Last success", "Next renewal"}, 0) {
        @Override public Class<?> getColumnClass(int column) { return column == 1 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int row, int column) { return column == 1; }
        @Override public void setValueAt(Object value, int row, int column) {
            if (!refreshing && column == 1 && row >= 0 && row < rows.size()) profiles.setEnabled(rows.get(row).name, Boolean.TRUE.equals(value));
            super.setValueAt(value, row, column);
        }
    };
    private final JTable table = new JTable(model) {
        @Override public String getToolTipText(java.awt.event.MouseEvent event) {
            int row = rowAtPoint(event.getPoint()), column = columnAtPoint(event.getPoint());
            return row < 0 || column < 0 ? null : String.valueOf(getValueAt(row, column));
        }
    };
    private final Timer timer;
    private JDialog profileDialog;
    private final JButton saveFile = new JButton("Save profiles...");
    private final JButton loadFile = new JButton("Load profiles...");
    private final JLabel fileStatus = new JLabel("Profile files include requests and token values in plain text.");
    private List<SessionProfile> rows = new ArrayList<>();
    public SessionProfilesPanel(JWTReauth extension) {
        super(new BorderLayout(8, 8)); this.extension = extension; profiles = extension.getSessionProfiles();
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(new JLabel("Active profiles modify requests using exactly one matching mode: Scope or Marker. Hover over a rule to see its full value."), BorderLayout.NORTH);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        add(new JScrollPane(table), BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton create = new JButton("New profile"); create.addActionListener(e -> edit(null, null)); actions.add(create);
        JButton edit = new JButton("Edit selected"); edit.addActionListener(e -> { SessionProfile p = selected(); if (p != null) edit(p, null); }); actions.add(edit);
        JButton test = new JButton("Renew now"); test.addActionListener(e -> { SessionProfile p = selected(); if (p != null) profiles.test(p.name); }); actions.add(test);
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
    /** Updates only changed cells so selection, editing, and tooltips survive the periodic refresh. */
    private void refresh() {
        if (table.isEditing()) return;
        SessionProfile selected = selected(); rows = profiles.list();
        refreshing = true;
        try {
            if (model.getRowCount() != rows.size()) model.setRowCount(rows.size());
            for (int row = 0; row < rows.size(); row++) {
                SessionProfile p = rows.get(row);
                Object[] cells = {p.name, p.enabled, p.autoMatch ? "Scope" : "Marker + scope",
                        p.autoMatch ? p.describeScope() : SessionProfiles.MARKER + ": " + p.name + " (within " + p.describeScope() + ")",
                        p.enabled ? p.status : "Inactive — " + p.status,
                        p.lastSuccess == null ? "Never" : p.lastSuccess.toString(), p.nextRenewal == null ? "—" : p.nextRenewal.toString()};
                for (int column = 0; column < cells.length; column++)
                    if (!java.util.Objects.equals(model.getValueAt(row, column), cells[column])) model.setValueAt(cells[column], row, column);
            }
        } finally { refreshing = false; }
        int index = selected == null ? -1 : rows.stream().map(p -> p.name).collect(java.util.stream.Collectors.toList()).indexOf(selected.name);
        if (index >= 0 && table.getSelectedRow() != index) table.setRowSelectionInterval(index, index);
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
    public void importLoginRequest(IHttpRequestResponse message) { importWorkflowRequest(message, true); }
    public void importRefreshRequest(IHttpRequestResponse message) { importWorkflowRequest(message, false); }
    private void importWorkflowRequest(IHttpRequestResponse message, boolean login) {
        if (profileDialog != null && profileDialog.isDisplayable()) { profileDialog.toFront(); return; }
        List<SessionProfile> current = profiles.list();
        List<String> options = new ArrayList<>(); options.add("Create new profile");
        current.forEach(p -> options.add(p.name));
        Object chosen = JOptionPane.showInputDialog(this, "Set " + (login ? "login" : "refresh") + " request for:", "JWT re-auth request",
                JOptionPane.PLAIN_MESSAGE, null, options.toArray(), options.get(0));
        if (chosen == null) return;
        SessionProfile selected = current.stream().filter(p -> p.name.equals(chosen)).findFirst().orElse(null);
        edit(selected, message, login);
    }
    private void edit(SessionProfile existing, IHttpRequestResponse imported) { edit(existing, imported, false); }
    private void edit(SessionProfile existing, IHttpRequestResponse imported, boolean loginImport) {
        if (profileDialog != null && profileDialog.isDisplayable()) { profileDialog.toFront(); return; }
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(this), "Session profile", Dialog.ModalityType.APPLICATION_MODAL);
        profileDialog = dialog;
        JPanel content = new JPanel(new BorderLayout(8, 8)); content.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel fields = new JPanel(new GridLayout(0, 2, 6, 6));
        JTextField name = new JTextField(existing == null ? "" : existing.name);
        String importedUrl = imported == null ? "https://example.test/refresh" : extension.getCallbacks().getHelpers().analyzeRequest(imported).getUrl().toString();
        // A login import must not become the renewal URL; only a refresh import replaces it.
        boolean refreshImport = imported != null && !loginImport;
        JTextField endpoint = new JTextField(refreshImport ? importedUrl : existing != null ? existing.endpoint.toString() : "https://example.test/refresh");
        // Prefilled URL for new scope rows: the imported request's origin, else the profile's first rule's origin.
        String defaultScope = imported != null ? origin(extension.getCallbacks().getHelpers().analyzeRequest(imported).getUrl())
                : existing != null && !existing.scope.isEmpty() ? origin(existing.scope.get(0).url) : "https://example.test/";
        JSpinner interval = new JSpinner(new SpinnerNumberModel(existing == null ? 300 : existing.interval, 5, 86400, 5));
        JComboBox<ReauthHttpClient.Protocol> protocol = new JComboBox<>(ReauthHttpClient.Protocol.values());
        protocol.setSelectedItem(existing == null ? ReauthHttpClient.Protocol.AUTO : existing.protocol);
        // Index 0 is Scope mode (autoMatch); both modes apply the Scope tab's rules.
        JComboBox<String> matchBy = new JComboBox<>(new String[]{"In scope (no marker)", "With marker, in scope"});
        matchBy.setSelectedIndex(existing != null && existing.autoMatch ? 0 : 1);
        JTextField marker = new JTextField(); marker.setEditable(false);
        Runnable updateRule = () -> {
            boolean byScope = matchBy.getSelectedIndex() == 0;
            marker.setText(SessionProfiles.MARKER + ": " + name.getText().trim());
            marker.setEnabled(!byScope);
        };
        matchBy.addActionListener(e -> updateRule.run());
        name.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateRule.run(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateRule.run(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateRule.run(); }
        });
        updateRule.run();
        fields.add(new JLabel("Profile name (e.g. alice)")); fields.add(name);
        fields.add(new JLabel("Renewal URL (destination service)")); fields.add(endpoint);
        fields.add(new JLabel("Modify requests")); fields.add(matchBy);
        fields.add(new JLabel("Required marker header")); fields.add(marker);
        fields.add(new JLabel("Renew every (seconds)")); fields.add(interval);
        fields.add(new JLabel("HTTP protocol")); fields.add(protocol);
        content.add(fields, BorderLayout.NORTH);

        String raw = existing == null ? "GET /refresh HTTP/1.1\r\nHost: example.test\r\n\r\n" : existing.request;
        IMessageEditor requestEditor = new ProfileRequestEditor(extension.getCallbacks(), endpoint::getText,
                imported == null || loginImport ? extension.getCallbacks().getHelpers().stringToBytes(raw) : imported.getRequest()).editor;
        JTextField loginUrl = new JTextField(existing == null || existing.loginEndpoint == null ? "" : existing.loginEndpoint.toString());
        if (loginImport) loginUrl.setText(extension.getCallbacks().getHelpers().analyzeRequest(imported).getUrl().toString());
        JCheckBox useLogin = new JCheckBox("Use login before refresh", loginImport || existing != null && !existing.loginRequest.isBlank());
        String loginRaw = existing != null && !existing.loginRequest.isBlank() ? existing.loginRequest : "POST /login HTTP/1.1\r\nHost: example.test\r\n\r\n";
        IMessageEditor loginEditor = new ProfileRequestEditor(extension.getCallbacks(), loginUrl::getText,
                loginImport ? imported.getRequest() : extension.getCallbacks().getHelpers().stringToBytes(loginRaw)).editor;
        JPanel loginSettings = new JPanel(new GridLayout(0, 1)); loginSettings.add(useLogin); loginSettings.add(new JLabel("Login destination URL:")); loginSettings.add(loginUrl);
        JPanel loginPanel = new JPanel(new BorderLayout()); loginPanel.add(loginSettings, BorderLayout.NORTH); loginPanel.add(loginEditor.getComponent(), BorderLayout.CENTER);
        loginUrl.setToolTipText("Login destination URL; uncheck Use login before refresh for refresh-only operation");
        DefaultTableModel scopeRows = new DefaultTableModel(new String[]{"Action", "Match", "URL"}, 0);
        if (existing == null) scopeRows.addRow(new Object[]{ScopeRule.Action.INCLUDE, ScopeRule.Match.PREFIX, defaultScope});
        else for (ScopeRule r : existing.scope) scopeRows.addRow(new Object[]{r.action, r.match, r.url.toString()});
        JTable scopeTable = new JTable(scopeRows);
        scopeTable.setRowHeight(25);
        scopeTable.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JComboBox<>(ScopeRule.Action.values())));
        scopeTable.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(new JComboBox<>(ScopeRule.Match.values())));
        scopeTable.getColumnModel().getColumn(0).setMaxWidth(110); scopeTable.getColumnModel().getColumn(1).setMaxWidth(110);
        JCheckBox burpScope = new JCheckBox("Also include Burp target scope", existing != null && existing.burpScope);
        JPanel scopesPanel = new JPanel(new BorderLayout(5, 5));
        scopesPanel.add(new JLabel("Both modes use these rules: Scope mode modifies unmarked matching requests; Marker mode modifies marked requests that also match. PREFIX includes the path and everything below it; EXACT the path only (queries are ignored). EXCLUDE rules win."), BorderLayout.NORTH);
        scopesPanel.add(new JScrollPane(scopeTable), BorderLayout.CENTER);
        JPanel scopeButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addInclude = new JButton("Add include"); addInclude.addActionListener(e -> scopeRows.addRow(new Object[]{ScopeRule.Action.INCLUDE, ScopeRule.Match.PREFIX, defaultScope})); scopeButtons.add(addInclude);
        JButton addExclude = new JButton("Add exclude"); addExclude.addActionListener(e -> scopeRows.addRow(new Object[]{ScopeRule.Action.EXCLUDE, ScopeRule.Match.PREFIX, defaultScope})); scopeButtons.add(addExclude);
        JButton removeScope = new JButton("Remove row"); removeScope.addActionListener(e -> { if (scopeTable.getSelectedRow() >= 0) scopeRows.removeRow(scopeTable.getSelectedRow()); }); scopeButtons.add(removeScope);
        scopeButtons.add(burpScope);
        scopesPanel.add(scopeButtons, BorderLayout.SOUTH);
        JTabbedPane workflow = new JTabbedPane(); workflow.addTab("Refresh request", requestEditor.getComponent());
        workflow.addTab("Login request (optional)", loginPanel); workflow.addTab("Scope", scopesPanel);
        if (loginImport) workflow.setSelectedComponent(loginPanel);
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
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, workflow, extraction); split.setResizeWeight(.55); content.add(split, BorderLayout.CENTER);
        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(new JLabel("Initial values bootstrap renewal. Values are inserted literally. Use Save profiles to persist settings and values. See Tokens for current values and Debugging for renewal exchanges."), BorderLayout.NORTH);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton cancel = new JButton("Cancel"); cancel.addActionListener(e -> dialog.dispose()); buttons.add(cancel);
        for (String action : new String[]{"Save", "Save and test"}) {
            JButton save = new JButton(action); save.addActionListener(e -> {
                try {
                    if (ruleTable.isEditing() && !ruleTable.getCellEditor().stopCellEditing()) return;
                    if (scopeTable.isEditing() && !scopeTable.getCellEditor().stopCellEditing()) return;
                    List<ScopeRule> scope = new ArrayList<>();
                    for (int row = 0; row < scopeRows.getRowCount(); row++) {
                        URL url;
                        try { url = new URL(cell(scopeRows, row, 2).trim()); }
                        catch (java.net.MalformedURLException invalid) { throw new IllegalArgumentException("Scope row " + (row + 1) + ": enter a full URL such as https://example.test/api"); }
                        scope.add(new ScopeRule(ScopeRule.Action.valueOf(cell(scopeRows, row, 0)), ScopeRule.Match.valueOf(cell(scopeRows, row, 1)), url));
                    }
                    List<SessionProfile.Rule> definitions = new ArrayList<>();
                    for (int row = 0; row < rules.getRowCount(); row++) definitions.add(new SessionProfile.Rule(
                            cell(rules, row, 0), SessionProfile.Source.valueOf(cell(rules, row, 1)), cell(rules, row, 2), cell(rules, row, 3),
                            SessionProfile.Destination.valueOf(cell(rules, row, 4)), cell(rules, row, 5), cell(rules, row, 6)));
                    SessionProfile profile = new SessionProfile(name.getText().trim(), new URL(endpoint.getText().trim()), scope, burpScope.isSelected(),
                            extension.getCallbacks().getHelpers().bytesToString(requestEditor.getMessage()), ((Number) interval.getValue()).intValue(), definitions, existing != null && existing.enabled, matchBy.getSelectedIndex() == 0, (ReauthHttpClient.Protocol) protocol.getSelectedItem());
                    String login = useLogin.isSelected() ? extension.getCallbacks().getHelpers().bytesToString(loginEditor.getMessage()) : "";
                    profile.configureWorkflow(login, loginUrl.getText().isBlank() ? null : new URL(loginUrl.getText().trim()));
                    profiles.save(profile, existing == null ? null : existing.name);
                    if (action.equals("Save and test") && !profile.enabled) profiles.test(profile.name);
                    refresh(); dialog.dispose();
                } catch (Exception ex) { JOptionPane.showMessageDialog(dialog, ex.getMessage(), "Invalid profile", JOptionPane.ERROR_MESSAGE); }
            }); buttons.add(save);
        }
        bottom.add(buttons, BorderLayout.SOUTH); content.add(bottom, BorderLayout.SOUTH);
        dialog.setContentPane(content); dialog.setSize(1150, 780); dialog.setLocationRelativeTo(this);
        try { dialog.setVisible(true); } finally { profileDialog = null; }
    }
    private static String cell(DefaultTableModel model, int row, int col) { Object value = model.getValueAt(row, col); return value == null ? "" : value.toString(); }
    private static String origin(URL url) { return url.getProtocol() + "://" + url.getAuthority() + "/"; }
    @Override public void extensionUnloaded() { SwingUtilities.invokeLater(timer::stop); }
}
