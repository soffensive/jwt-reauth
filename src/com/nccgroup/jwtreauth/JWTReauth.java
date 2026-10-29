/*
Copyright 2022 NCC Group
Modified in the soffensive/jwt-reauth fork (2026): initialize independent session profiles and their UI.
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

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import com.nccgroup.jwtreauth.ui.logging.LogController;
import com.nccgroup.jwtreauth.ui.scope.ScopeController;
import com.nccgroup.jwtreauth.ui.settings.SettingsController;
import com.nccgroup.jwtreauth.ui.state.TokenListenerStatePanel;

import javax.swing.*;

public class JWTReauth implements IBurpExtender {
    private static final String VERSION = "1.0.1";

    private IBurpExtenderCallbacks callbacks;
    private LogController logController;
    private ScopeController scopeController;
    private SettingsController settingsController;
    private TokenListenerStatePanel tokenListenerStatePanel;
    private TokenListener tokenListener;
    private SessionProfiles sessionProfiles;
    private com.nccgroup.jwtreauth.ui.SessionProfilesPanel sessionProfilesPanel;
    private MainViewController mainViewController;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        logController = new LogController();
        scopeController = new ScopeController();
        tokenListener = new TokenListener(this);
        tokenListenerStatePanel = tokenListener.getTokenListenerStatePanel();
        settingsController = new SettingsController(this);
        tokenListener.setSettingsController(settingsController);
        sessionProfiles = new SessionProfiles(this);
        sessionProfilesPanel = new com.nccgroup.jwtreauth.ui.SessionProfilesPanel(this);
        callbacks.registerExtensionStateListener(sessionProfiles);
        mainViewController = new MainViewController(this);

        callbacks.setExtensionName("JWT re-auth");
        callbacks.registerHttpListener(tokenListener);
        callbacks.registerContextMenuFactory(new JWTReauthContextMenuFactory(this));
        callbacks.registerExtensionStateListener(tokenListener);
        callbacks.registerExtensionStateListener(tokenListenerStatePanel);

        SwingUtilities.invokeLater(() -> {
            callbacks.addSuiteTab(mainViewController);
            callbacks.printOutput("Loaded JWT re-auth. v" + VERSION);
        });
    }

    public SessionProfiles getSessionProfiles() { return sessionProfiles; }
    public com.nccgroup.jwtreauth.ui.SessionProfilesPanel getSessionProfilesPanel() { return sessionProfilesPanel; }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public LogController getLogController() {
        return logController;
    }

    public ScopeController getScopeController() {
        return scopeController;
    }

    public SettingsController getSettingsController() {
        return settingsController;
    }

    public TokenListener getTokenListener() {
        return tokenListener;
    }

    public TokenListenerStatePanel getTokenListenerStatePanel() {
        return tokenListenerStatePanel;
    }
}
