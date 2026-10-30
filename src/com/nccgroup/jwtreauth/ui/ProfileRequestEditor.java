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
import java.net.URL;
import java.util.function.Supplier;

/** Gives Burp's native editor a complete context for its menus and hotkeys. */
public final class ProfileRequestEditor implements IMessageEditorController {
    public final IMessageEditor editor;
    private final IExtensionHelpers helpers;
    private final Supplier<String> destination;
    private final byte[] initial;
    private final IHttpService fallback;
    public ProfileRequestEditor(IBurpExtenderCallbacks callbacks, Supplier<String> destination, byte[] initial) {
        this.helpers = callbacks.getHelpers(); this.destination = destination; this.initial = initial.clone();
        fallback = helpers.buildHttpService("example.test", 443, "https");
        editor = callbacks.createMessageEditor(this, true);
        editor.setMessage(this.initial, true);
    }
    @Override public IHttpService getHttpService() {
        try {
            URL url = new URL(destination.get());
            if (!url.getProtocol().matches("https?")) return fallback;
            return helpers.buildHttpService(url.getHost(), url.getPort() < 0 ? url.getDefaultPort() : url.getPort(), url.getProtocol());
        } catch (Exception ex) { return fallback; }
    }
    @Override public byte[] getRequest() {
        byte[] current = editor == null ? initial : editor.getMessage();
        return current == null || current.length == 0 ? initial : current;
    }
    @Override public byte[] getResponse() { return new byte[0]; }
}
