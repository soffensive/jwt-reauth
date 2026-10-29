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

import burp.IExtensionStateListener;
import burp.IExtensionHelpers;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IHttpService;
import java.net.URL;
import com.nccgroup.jwtreauth.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class RequestDebugPanel extends JPanel implements IExtensionStateListener {
    private final SessionProfiles profiles;
    private final RequestDebugLog log;
    private final DefaultTableModel model = new DefaultTableModel(new String[]{"Time", "Type", "Profile", "URL", "Changed", "Result"}, 0) {
        @Override public boolean isCellEditable(int row, int column) { return false; }
    };
    private final JTable table = new JTable(model);
    private final IMessageEditor before, after;
    private final ViewerContext beforeContext = new ViewerContext(), afterContext = new ViewerContext();
    private final IExtensionHelpers helpers;
    private final JTextArea details = textArea(), tokens = textArea();
    private final JCheckBox follow = new JCheckBox("Follow latest", true);
    private final Timer timer;
    private List<RequestDebugLog.Event> rows = new ArrayList<>();
    private long revision = -1;

    public RequestDebugPanel(JWTReauth extension) {
        super(new BorderLayout(5, 5));
        profiles = extension.getSessionProfiles(); log = profiles.getDebugLog();
        helpers = extension.getCallbacks().getHelpers();
        before = extension.getCallbacks().createMessageEditor(beforeContext, false);
        after = extension.getCallbacks().createMessageEditor(afterContext, false);
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JTextField search = new JTextField(25);
        controls.add(new JLabel("Filter:")); controls.add(search); controls.add(follow);
        JButton clear = new JButton("Clear history"); clear.addActionListener(e -> { log.clear(); refresh(); }); controls.add(clear);
        add(controls, BorderLayout.NORTH);
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model); table.setRowSorter(sorter);
        search.getDocument().addDocumentListener(new DocumentListener() {
            private void update() { sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(search.getText()))); }
            public void insertUpdate(DocumentEvent e) { update(); }
            public void removeUpdate(DocumentEvent e) { update(); }
            public void changedUpdate(DocumentEvent e) { update(); }
        });
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) showSelected(); });
        JTabbedPane inspection = new JTabbedPane();
        JSplitPane comparison = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, labeled("Before extension changes", before.getComponent()), labeled("After extension changes", after.getComponent()));
        comparison.setResizeWeight(.5);
        inspection.addTab("Request before / after", comparison);
        inspection.addTab("Decision / renewal response", new JScrollPane(details));
        inspection.addTab("Current tokens and variables", new JScrollPane(tokens));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), inspection);
        split.setResizeWeight(.4); add(split, BorderLayout.CENTER);
        add(new JLabel("Latest 200 events. Request/response views show up to 64 KiB. Tokens and credentials are visible."), BorderLayout.SOUTH);
        timer = new Timer(500, e -> refresh()); timer.start(); refresh();
        extension.getCallbacks().registerExtensionStateListener(this);
    }
    private static JTextArea textArea() {
        JTextArea area = new JTextArea(); area.setEditable(false); area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12)); return area;
    }
    private static JPanel labeled(String label, Component viewer) {
        JPanel panel = new JPanel(new BorderLayout()); panel.add(new JLabel(label), BorderLayout.NORTH); panel.add(viewer, BorderLayout.CENTER); return panel;
    }
    private static final class ViewerContext implements IMessageEditorController {
        private volatile IHttpService service;
        private volatile byte[] request;
        @Override public IHttpService getHttpService() { return service; }
        @Override public byte[] getRequest() { return request; }
        @Override public byte[] getResponse() { return null; }
    }
    private void display(IMessageEditor viewer, ViewerContext context, String request, IHttpService service) {
        context.service = service;
        context.request = request == null || request.isEmpty() ? null : helpers.stringToBytes(request);
        // Some Burp versions reject null when clearing a native message viewer.
        viewer.setMessage(context.request == null ? new byte[0] : context.request, true);
    }
    private void showSelected() {
        int selected = table.getSelectedRow();
        if (selected < 0) {
            display(before, beforeContext, null, null); display(after, afterContext, null, null);
            details.setText(""); return;
        }
        RequestDebugLog.Event event = rows.get(table.convertRowIndexToModel(selected));
        IHttpService service = null;
        try {
            URL url = new URL(event.url);
            service = helpers.buildHttpService(url.getHost(), SessionProfile.port(url), url.getProtocol());
        } catch (java.net.MalformedURLException ignored) { }
        display(before, beforeContext, event.before, service);
        display(after, afterContext, event.after, service);
        details.setText(event.reason + "\n\n" + event.details);
        details.setCaretPosition(0);
    }
    private void refresh() {
        StringBuilder state = new StringBuilder();
        for (SessionProfile p : profiles.list()) {
            state.append(p.name).append(" — ").append(p.status).append(p.lastSuccess == null ? " (awaiting renewal)" : "").append("\n");
            Map<String, String> values = p.snapshot();
            for (SessionProfile.Rule rule : p.rules) {
                state.append("  ").append(rule.variable).append(" = ").append(values.get(rule.variable)).append("\n");
                if (rule.destination != SessionProfile.Destination.VARIABLE)
                    state.append("    ").append(rule.destination).append(" ").append(rule.target).append(": ").append(rule.prefix).append(values.get(rule.variable)).append("\n");
            }
            state.append("\n");
        }
        String rendered = state.length() == 0 ? "No session profiles configured." : state.toString();
        if (!tokens.getText().equals(rendered)) { int caret = tokens.getCaretPosition(); tokens.setText(rendered); tokens.setCaretPosition(Math.min(caret, rendered.length())); }
        long latest = log.revision(); if (latest == revision) return;
        long selectedId = -1;
        if (table.getSelectedRow() >= 0) selectedId = rows.get(table.convertRowIndexToModel(table.getSelectedRow())).id;
        rows = log.snapshot(); revision = latest; model.setRowCount(0);
        for (RequestDebugLog.Event event : rows) model.addRow(new Object[]{event.time, event.kind, event.profile, event.url, event.changed ? "Yes" : "No", event.reason});
        int target = -1;
        for (int i = 0; i < rows.size(); i++) if (follow.isSelected() || rows.get(i).id == selectedId) {
            int view = table.convertRowIndexToView(i); if (view >= 0) target = view;
        }
        if (target >= 0) { table.setRowSelectionInterval(target, target); if (follow.isSelected()) table.scrollRectToVisible(table.getCellRect(target, 0, true)); }
        else showSelected();
    }
    @Override public void extensionUnloaded() { SwingUtilities.invokeLater(timer::stop); }
}
