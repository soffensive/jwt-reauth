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
import java.util.Map;

/** Live values are independent of the selected debug event and debug history. */
public final class TokenValuesPanel extends JPanel implements IExtensionStateListener {
    private final SessionProfiles profiles;
    private final JTextArea values = new JTextArea();
    private final Timer timer;
    public TokenValuesPanel(JWTReauth extension) {
        super(new BorderLayout(5, 5)); profiles = extension.getSessionProfiles();
        values.setEditable(false); values.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        add(new JLabel("Current tokens and variables for all profiles (plain text, copyable)."), BorderLayout.NORTH);
        add(new JScrollPane(values), BorderLayout.CENTER);
        timer = new Timer(500, e -> refresh()); timer.start(); refresh();
        extension.getCallbacks().registerExtensionStateListener(this);
    }
    private void refresh() {
        StringBuilder state = new StringBuilder();
        for (SessionProfile profile : profiles.list()) {
            state.append(profile.name).append(profile.enabled ? " (active) — " : " (inactive) — ").append(profile.status)
                    .append(profile.lastSuccess == null ? " (awaiting renewal)" : "").append("\n");
            Map<String, String> snapshot = profile.snapshot();
            for (SessionProfile.Rule rule : profile.rules) {
                state.append("  ").append(rule.variable).append(" = ").append(snapshot.get(rule.variable)).append("\n");
                if (rule.destination != SessionProfile.Destination.VARIABLE)
                    state.append("    ").append(rule.destination).append(" ").append(rule.target).append(": ")
                            .append(rule.prefix).append(snapshot.get(rule.variable)).append("\n");
            }
            state.append("\n");
        }
        String text = state.length() == 0 ? "No session profiles configured." : state.toString();
        if (!values.getText().equals(text)) {
            int caret = values.getCaretPosition(); values.setText(text); values.setCaretPosition(Math.min(caret, text.length()));
        }
    }
    @Override public void extensionUnloaded() { SwingUtilities.invokeLater(timer::stop); }
}
