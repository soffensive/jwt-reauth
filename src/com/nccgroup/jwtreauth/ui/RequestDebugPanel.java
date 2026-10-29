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
    private final JTextArea details = textArea();
    private final JTabbedPane inspection = new JTabbedPane();
    private final JLabel leftLabel = new JLabel("Before extension changes"), rightLabel = new JLabel("After extension changes");
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
        JSplitPane comparison = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, labeled(leftLabel, before.getComponent()), labeled(rightLabel, after.getComponent()));
        comparison.setResizeWeight(.5);
        inspection.addTab("Request before / after", comparison);
        inspection.addTab("Details", new JScrollPane(details));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), inspection);
        split.setResizeWeight(.4); add(split, BorderLayout.CENTER);
        add(new JLabel("Latest 200 events. Request/response views show up to 64 KiB. Tokens and credentials are visible."), BorderLayout.SOUTH);
        timer = new Timer(500, e -> refresh()); timer.start(); refresh();
        extension.getCallbacks().registerExtensionStateListener(this);
    }
    private static JTextArea textArea() {
        JTextArea area = new JTextArea(); area.setEditable(false); area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12)); return area;
    }
    private static JPanel labeled(JLabel label, Component viewer) {
        JPanel panel = new JPanel(new BorderLayout()); panel.add(label, BorderLayout.NORTH); panel.add(viewer, BorderLayout.CENTER); return panel;
    }
    private static final class ViewerContext implements IMessageEditorController {
        private volatile IHttpService service;
        private volatile byte[] request, response;
        @Override public IHttpService getHttpService() { return service; }
        @Override public byte[] getRequest() { return request; }
        @Override public byte[] getResponse() { return response; }
    }
    private void display(IMessageEditor viewer, ViewerContext context, String request, String response, IHttpService service, boolean isRequest) {
        context.service = service;
        context.request = request == null || request.isEmpty() ? null : helpers.stringToBytes(request);
        context.response = response == null || response.isEmpty() ? null : helpers.stringToBytes(response);
        byte[] message = isRequest ? context.request : context.response;
        viewer.setMessage(message == null ? new byte[0] : message, isRequest);
    }
    private void showSelected() {
        int selected = table.getSelectedRow();
        if (selected < 0) {
            display(before, beforeContext, null, null, null, true); display(after, afterContext, null, null, null, true);
            details.setText(""); return;
        }
        RequestDebugLog.Event event = rows.get(table.convertRowIndexToModel(selected));
        IHttpService service = null;
        try {
            URL url = new URL(event.url);
            service = helpers.buildHttpService(url.getHost(), SessionProfile.port(url), url.getProtocol());
        } catch (java.net.MalformedURLException ignored) { }
        boolean renewal = event.kind.equals("Renewal");
        inspection.setTitleAt(0, renewal ? "Renewal request / response" : "Request before / after");
        leftLabel.setText(renewal ? "Renewal request" : "Before extension changes");
        rightLabel.setText(renewal ? "Renewal response" : "After extension changes");
        display(before, beforeContext, event.before, renewal ? event.response : null, service, true);
        display(after, afterContext, renewal ? event.before : event.after, renewal ? event.response : null, service, !renewal);
        details.setText(event.reason + "\n\n" + event.details);
        details.setCaretPosition(0);
    }
    private void refresh() {
        long latest = log.revision(); if (latest == revision) return;
        long selectedId = -1;
        if (table.getSelectedRow() >= 0) selectedId = rows.get(table.convertRowIndexToModel(table.getSelectedRow())).id;
        rows = log.snapshot(); revision = latest; model.setRowCount(0);
        for (RequestDebugLog.Event event : rows) model.addRow(new Object[]{event.time, event.kind, event.profile, event.url, event.kind.equals("Renewal") ? "—" : event.changed ? "Yes" : "No", event.reason});
        int target = -1;
        for (int i = 0; i < rows.size(); i++) if (follow.isSelected() || rows.get(i).id == selectedId) {
            int view = table.convertRowIndexToView(i); if (view >= 0) target = view;
        }
        if (target >= 0) { table.setRowSelectionInterval(target, target); if (follow.isSelected()) table.scrollRectToVisible(table.getCellRect(target, 0, true)); }
        else showSelected();
    }
    @Override public void extensionUnloaded() { SwingUtilities.invokeLater(timer::stop); }
}
