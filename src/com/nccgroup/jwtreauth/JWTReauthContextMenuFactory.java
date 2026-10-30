/*
Copyright 2022 NCC Group
Modified in the soffensive/jwt-reauth fork (2026): provide a single profile-import context menu action.
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

package com.nccgroup.jwtreauth;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import javax.swing.JMenuItem;
import java.util.Collections;
import java.util.List;

public class JWTReauthContextMenuFactory implements IContextMenuFactory {
    private final JWTReauth extension;
    public JWTReauthContextMenuFactory(JWTReauth extension) { this.extension = extension; }
    @Override public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        switch (invocation.getInvocationContext()) {
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            case IContextMenuInvocation.CONTEXT_PROXY_HISTORY:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE:
            case IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE:
                JMenuItem item = new JMenuItem("Send to JWT re-auth (create session profile)");
                item.addActionListener(event -> {
                    var messages = invocation.getSelectedMessages();
                    if (messages != null && messages.length == 1) extension.getSessionProfilesPanel().importRequest(messages[0]);
                });
                JMenuItem login = new JMenuItem("Send to JWT re-auth (set login request)");
                login.addActionListener(event -> {
                    var messages = invocation.getSelectedMessages();
                    if (messages != null && messages.length == 1) extension.getSessionProfilesPanel().importLoginRequest(messages[0]);
                    else javax.swing.JOptionPane.showMessageDialog(null, "Select one request to set as the login request.");
                });
                JMenuItem refresh = new JMenuItem("Send to JWT re-auth (set refresh request)");
                refresh.addActionListener(event -> {
                    var messages = invocation.getSelectedMessages();
                    if (messages != null && messages.length == 1) extension.getSessionProfilesPanel().importRefreshRequest(messages[0]);
                    else javax.swing.JOptionPane.showMessageDialog(null, "Select one request to set as the refresh request.");
                });
                return java.util.Arrays.asList(item, login, refresh);
            default: return null;
        }
    }
}
