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
import com.nccgroup.jwtreauth.*;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Live values are independent of the selected debug event and debug history. Each value wraps in its
 * own field, so long tokens need no horizontal scrolling and copy as one unbroken line.
 */
public final class TokenValuesPanel extends JPanel implements IExtensionStateListener {
    private static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 12);
    private final SessionProfiles profiles;
    private final Rows rows = new Rows();
    private final Timer timer;
    // Rebuilt only when profiles or rules change, so selections survive value refreshes.
    private String layout;
    private final Map<String, JLabel> statuses = new HashMap<>();
    private final Map<String, JTextArea> values = new HashMap<>();

    /** Tracks the viewport width so wrapping fields never widen the panel. */
    private static final class Rows extends JPanel implements Scrollable {
        Rows() { setLayout(new BoxLayout(this, BoxLayout.Y_AXIS)); setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6)); }
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle visible, int orientation, int direction) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle visible, int orientation, int direction) { return visible.height; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }

    public TokenValuesPanel(JWTReauth extension) {
        super(new BorderLayout(5, 5)); profiles = extension.getSessionProfiles();
        add(new JLabel("Current tokens and variables for all profiles (plain text). Copy buttons copy the full value."), BorderLayout.NORTH);
        JScrollPane scroll = new JScrollPane(rows, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        add(scroll, BorderLayout.CENTER);
        timer = new Timer(500, e -> refresh()); timer.start(); refresh();
        extension.getCallbacks().registerExtensionStateListener(this);
    }
    private static String key(SessionProfile profile, SessionProfile.Rule rule) { return profile.name + "\u0000" + rule.variable; }
    private static String status(SessionProfile profile) {
        return (profile.enabled ? "active — " : "inactive — ") + profile.status + (profile.lastSuccess == null ? " (awaiting renewal)" : "");
    }
    /** What a request actually carries for this rule, or null for renewal-only variables. */
    private static String sent(SessionProfile.Rule rule, String value) {
        switch (rule.destination) {
            case HEADER: return rule.target + ": " + rule.prefix + value;
            case COOKIE: return rule.target + "=" + rule.prefix + value;
            default: return null;
        }
    }
    private void refresh() {
        List<SessionProfile> current = profiles.list();
        StringBuilder signature = new StringBuilder();
        for (SessionProfile p : current) {
            signature.append(p.name).append('\n');
            for (SessionProfile.Rule r : p.rules) signature.append(' ').append(r.variable).append(r.destination).append(r.target).append(r.prefix).append('\n');
        }
        if (!signature.toString().equals(layout)) { rebuild(current); layout = signature.toString(); }
        for (SessionProfile p : current) {
            JLabel label = statuses.get(p.name);
            if (label != null && !label.getText().equals(status(p))) label.setText(status(p));
            Map<String, String> snapshot = p.snapshot();
            for (SessionProfile.Rule r : p.rules) {
                JTextArea field = values.get(key(p, r));
                String value = String.valueOf(snapshot.get(r.variable));
                if (field != null && !field.getText().equals(value)) field.setText(value);
            }
        }
    }
    private void rebuild(List<SessionProfile> current) {
        rows.removeAll(); statuses.clear(); values.clear();
        if (current.isEmpty()) rows.add(left(new JLabel("No session profiles configured.")));
        for (SessionProfile p : current) {
            JLabel title = new JLabel(p.name); title.setFont(title.getFont().deriveFont(Font.BOLD));
            JLabel state = new JLabel(status(p)); statuses.put(p.name, state);
            JPanel heading = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2)); heading.add(title); heading.add(state);
            rows.add(left(heading));
            for (SessionProfile.Rule r : p.rules) rows.add(left(row(p, r)));
            rows.add(Box.createVerticalStrut(10));
        }
        rows.revalidate(); rows.repaint();
    }
    private JComponent row(SessionProfile profile, SessionProfile.Rule rule) {
        JTextArea field = new JTextArea();
        field.setEditable(false); field.setFont(MONO);
        // Character wrapping: tokens contain no spaces, and soft wraps are not part of the copied text.
        field.setLineWrap(true); field.setWrapStyleWord(false);
        field.setBorder(BorderFactory.createCompoundBorder(UIManager.getBorder("TextField.border"), BorderFactory.createEmptyBorder(2, 4, 2, 4)));
        values.put(key(profile, rule), field);
        String description = rule.variable + (rule.destination == SessionProfile.Destination.VARIABLE
                ? "  (renewal variable)" : "  →  " + rule.destination + " " + rule.target);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        JButton copyValue = new JButton("Copy value");
        copyValue.addActionListener(e -> copy(field.getText()));
        buttons.add(copyValue);
        if (rule.destination != SessionProfile.Destination.VARIABLE) {
            JButton copySent = new JButton(rule.destination == SessionProfile.Destination.HEADER ? "Copy header" : "Copy cookie");
            copySent.setToolTipText("Copies the " + rule.destination.toString().toLowerCase(Locale.ROOT) + " as sent, including any prefix");
            copySent.addActionListener(e -> copy(sent(rule, field.getText())));
            buttons.add(copySent);
        }
        JPanel top = new JPanel(new BorderLayout()); top.add(new JLabel(description), BorderLayout.WEST); top.add(buttons, BorderLayout.EAST);
        JPanel row = new JPanel(new BorderLayout(0, 2)) {
            // A wrapping text area knows its height only once it has a width; re-layout when they disagree.
            @Override public void doLayout() {
                super.doLayout();
                if (field.getWidth() > 0 && field.getPreferredSize().height != field.getHeight()) SwingUtilities.invokeLater(field::revalidate);
            }
        };
        row.setBorder(BorderFactory.createEmptyBorder(2, 16, 6, 0));
        row.add(top, BorderLayout.NORTH); row.add(field, BorderLayout.CENTER);
        return row;
    }
    private static JComponent left(JComponent component) { component.setAlignmentX(Component.LEFT_ALIGNMENT); return component; }
    private void copy(String text) {
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(text), null);
    }
    @Override public void extensionUnloaded() { SwingUtilities.invokeLater(timer::stop); }
}
