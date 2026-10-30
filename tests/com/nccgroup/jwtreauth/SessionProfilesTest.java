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

package com.nccgroup.jwtreauth;

import burp.*;
import com.nccgroup.jwtreauth.ui.logging.LogController;
import java.lang.reflect.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Integration checks using a small Burp API double; no network requests are sent. */
public final class SessionProfilesTest {
    private static final String RESPONSE = "HTTP/1.1 200 OK\r\nSet-Cookie: session=new-cookie; Path=/\r\nX-CSRF: csrf-value\r\n\r\n{\"data\":{\"access_token\":\"new-token\"},\"refresh_token\":\"rotated\"}";
    private static final String NO_MATCH = "HTTP/1.1 200 OK\r\n\r\n{\"error\":\"expired\"}";
    public static void main(String[] args) throws Exception {
        workflow(); scope(); extraction(); routing(); concurrency(); protocols(); persistence(); debugHistory(); startup();
        System.out.println("Session profile extraction, routing, and concurrency tests passed");
    }
    private static void startup() throws Exception {
        Fixture fixture = new Fixture();
        JWTReauth extension = new JWTReauth();
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> extension.registerExtenderCallbacks(fixture.callbacks));
            assert extension.getSessionProfiles() != null;
            assert extension.getSessionProfilesPanel() != null;
            assert fixture.editors.size() == 2;
            assert fixture.editors.stream().allMatch(editor -> editor.message != null && editor.message.length == 0)
                    : "Empty history must initialize viewers with an empty, non-null message";
            assert fixture.editors.stream().noneMatch(editor -> editor.editable);
            String original = "GET /api HTTP/2\r\nHost: example.test\r\n\r\n";
            String modified = "GET /api HTTP/2\r\nHost: example.test\r\nAuthorization: Bearer visible-token\r\n\r\n";
            extension.getSessionProfiles().getDebugLog().add("Request", "alice", "https://example.test/api", "Applied profile", original, modified, "");
            await(() -> Arrays.equals(fixture.editors.get(0).message, bytes(original)) && Arrays.equals(fixture.editors.get(1).message, bytes(modified)));
            assert fixture.editors.get(0).isRequest && fixture.editors.get(1).isRequest;
            assert Arrays.equals(fixture.editors.get(0).controller.getRequest(), bytes(original));
            assert Arrays.equals(fixture.editors.get(1).controller.getRequest(), bytes(modified));
            assert fixture.editors.get(1).controller.getHttpService().getHost().equals("example.test");
            extension.getSessionProfiles().getDebugLog().addRenewal("alice", "https://example.test/refresh", "Renewed", original, RESPONSE, "Extracted tokens");
            await(() -> Arrays.equals(fixture.editors.get(1).message, bytes(RESPONSE)));
            assert fixture.editors.get(0).isRequest && !fixture.editors.get(1).isRequest;
            assert Arrays.equals(fixture.editors.get(1).controller.getRequest(), bytes(original));
            assert Arrays.equals(fixture.editors.get(1).controller.getResponse(), bytes(RESPONSE));
            assert Arrays.equals(fixture.editors.get(0).controller.getResponse(), bytes(RESPONSE));
            String errorResponse = "HTTP/2 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"expired\"}";
            extension.getSessionProfiles().getDebugLog().addRenewal("alice", "https://example.test/refresh", "Failed", original, errorResponse, "HTTP 401");
            await(() -> Arrays.equals(fixture.editors.get(1).message, bytes(errorResponse)));
            assert !fixture.editors.get(1).isRequest;
            extension.getSessionProfiles().getDebugLog().addRenewal("alice", "https://example.test/refresh", "No response", original, "", "Connection failed");
            await(() -> fixture.editors.get(1).message.length == 0);
            assert Arrays.equals(fixture.editors.get(0).message, bytes(original));
            assert fixture.editors.get(1).controller.getResponse() == null;
            extension.getSessionProfiles().getDebugLog().add("Request", "alice", "https://example.test/api", "Applied profile", original, modified, "");
            await(() -> Arrays.equals(fixture.editors.get(1).message, bytes(modified)));
            assert fixture.editors.get(1).isRequest && fixture.editors.get(1).controller.getResponse() == null;
            extension.getSessionProfiles().getDebugLog().clear();
            await(() -> fixture.editors.get(0).message != null && fixture.editors.get(0).message.length == 0
                    && fixture.editors.get(1).message != null && fixture.editors.get(1).message.length == 0);
            assert fixture.editors.get(0).controller.getHttpService() == null;
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                javax.swing.JTabbedPane tabs = (javax.swing.JTabbedPane)new MainViewController(extension).getUiComponent();
                assert tabs.getTabCount() == 3 && tabs.getTitleAt(0).equals("Sessions")
                        && tabs.getTitleAt(1).equals("Tokens") && tabs.getTitleAt(2).equals("Debugging");
                assert tabs.getComponentAt(1) instanceof com.nccgroup.jwtreauth.ui.TokenValuesPanel;
            });
            SessionProfile tokenProfile = profile("visible", false, false);
            extension.getSessionProfiles().save(tokenProfile, null);
            await(() -> {
                java.util.concurrent.atomic.AtomicBoolean visible = new java.util.concurrent.atomic.AtomicBoolean();
                try {
                    javax.swing.SwingUtilities.invokeAndWait(() -> fixture.listeners.stream()
                            .filter(listener -> listener instanceof com.nccgroup.jwtreauth.ui.TokenValuesPanel)
                            .forEach(listener -> visible.set(visible.get() || hasText((java.awt.Component)listener, "seed-visible"))));
                } catch (Exception ex) { throw new AssertionError(ex); }
                return visible.get();
            });
            String longToken = "eyJ" + "a".repeat(3000);
            SessionProfile longProfile = new SessionProfile("long", tokenProfile.endpoint, tokenProfile.scope, false, tokenProfile.request, 3600,
                    Arrays.asList(new SessionProfile.Rule("token", SessionProfile.Source.JSON, "access_token", longToken, SessionProfile.Destination.HEADER, "Authorization", "Bearer "),
                            new SessionProfile.Rule("refresh", SessionProfile.Source.JSON, "refresh_token", "r", SessionProfile.Destination.VARIABLE, "")), false, false, ReauthHttpClient.Protocol.AUTO);
            extension.getSessionProfiles().save(longProfile, null);
            await(() -> {
                java.util.concurrent.atomic.AtomicBoolean wrapped = new java.util.concurrent.atomic.AtomicBoolean();
                try {
                    javax.swing.SwingUtilities.invokeAndWait(() -> fixture.listeners.stream()
                            .filter(listener -> listener instanceof com.nccgroup.jwtreauth.ui.TokenValuesPanel).forEach(listener -> {
                                java.awt.Component panel = (java.awt.Component)listener;
                                panel.setSize(600, 400); relayout(panel); relayout(panel);
                                javax.swing.JTextArea field = findText(panel, longToken);
                                if (field != null) wrapped.set(field.getText().equals(longToken) && field.getWidth() > 0 && field.getWidth() <= 600
                                        && field.getHeight() > 3 * field.getFontMetrics(field.getFont()).getHeight());
                            }));
                } catch (Exception ex) { throw new AssertionError(ex); }
                return wrapped.get();
            });
            extension.getSessionProfiles().remove("long");
            javax.swing.JTable overview = findTable(extension.getSessionProfilesPanel());
            await(() -> {
                java.util.concurrent.atomic.AtomicBoolean ready = new java.util.concurrent.atomic.AtomicBoolean();
                try { javax.swing.SwingUtilities.invokeAndWait(() -> ready.set(overview.getRowCount() == 1)); }
                catch (Exception ex) { throw new AssertionError(ex); }
                return ready.get();
            });
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                assert overview.getColumnName(1).equals("Active");
                assert overview.getValueAt(0, 2).equals("Marker + scope");
                assert overview.getValueAt(0, 3).toString().contains("X-Reauth-Profile: visible");
                assert overview.getValueAt(0, 3).toString().contains("https://example.test/api");
                assert overview.getColumnClass(1) == Boolean.class;
                assert overview.isCellEditable(0, 1) && !overview.isCellEditable(0, 0);
                overview.setValueAt(Boolean.TRUE, 0, 1);
            });
            assert tokenProfile.enabled;
            await(() -> tokenProfile.lastSuccess != null);
            Map<String, String> renewedValues = tokenProfile.snapshot();
            IHttpRequestResponse activeRequest = fixture.message("GET /api HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: visible\r\n\r\n");
            extension.getSessionProfiles().process(true, activeRequest);
            assert string(activeRequest.getRequest()).contains("Authorization: Bearer new-token");
            javax.swing.SwingUtilities.invokeAndWait(() -> overview.setValueAt(Boolean.FALSE, 0, 1));
            assert !tokenProfile.enabled && tokenProfile.nextRenewal == null;
            assert tokenProfile.snapshot() == renewedValues : "Activation must retain rotated credentials";
            IHttpRequestResponse inactiveRequest = fixture.message("GET /api HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: visible\r\n\r\n");
            extension.getSessionProfiles().process(true, inactiveRequest);
            assert !string(inactiveRequest.getRequest()).contains("Authorization:");
            IContextMenuInvocation invocation = proxy(IContextMenuInvocation.class, (p, m, a) ->
                    m.getName().equals("getInvocationContext") ? IContextMenuInvocation.CONTEXT_PROXY_HISTORY : null);
            List<javax.swing.JMenuItem> menu = new JWTReauthContextMenuFactory(extension).createMenuItems(invocation);
            assert menu.size() == 3;
            assert menu.stream().anyMatch(item -> item.getText().contains("set refresh request"));
            assert menu.stream().anyMatch(item -> item.getText().contains("set login request"));
        } finally {
            for (IExtensionStateListener listener : fixture.listeners) listener.extensionUnloaded();
            if (extension.getSessionProfiles() != null) extension.getSessionProfiles().extensionUnloaded();
            if (extension.getSessionProfilesPanel() != null) extension.getSessionProfilesPanel().extensionUnloaded();
        }
    }
    private static javax.swing.JTable findTable(java.awt.Component component) {
        if (component instanceof javax.swing.JTable) return (javax.swing.JTable)component;
        if (component instanceof java.awt.Container) for (java.awt.Component child : ((java.awt.Container)component).getComponents()) {
            javax.swing.JTable found = findTable(child); if (found != null) return found;
        }
        return null;
    }
    /** Headless components have no peer, so validate() is a no-op: drop cached sizes, then lay out top-down. */
    private static void relayout(java.awt.Component component) {
        component.invalidate();
        if (component instanceof java.awt.Container) {
            ((java.awt.Container)component).doLayout();
            for (java.awt.Component child : ((java.awt.Container)component).getComponents()) relayout(child);
        }
    }
    private static javax.swing.JTextArea findText(java.awt.Component component, String text) {
        if (component instanceof javax.swing.JTextArea && ((javax.swing.JTextArea)component).getText().equals(text)) return (javax.swing.JTextArea)component;
        if (component instanceof java.awt.Container) for (java.awt.Component child : ((java.awt.Container)component).getComponents()) {
            javax.swing.JTextArea found = findText(child, text); if (found != null) return found;
        }
        return null;
    }
    private static boolean hasText(java.awt.Component component, String expected) {
        if (component instanceof javax.swing.JTextArea && ((javax.swing.JTextArea)component).getText().contains(expected)) return true;
        if (component instanceof java.awt.Container) for (java.awt.Component child : ((java.awt.Container)component).getComponents())
            if (hasText(child, expected)) return true;
        return false;
    }
    private static SessionProfile profile(String name, boolean enabled, boolean automatic) throws Exception {
        return new SessionProfile(name, new URL("https://example.test/refresh"), new URL("https://example.test/api"),
                "POST /refresh HTTP/1.1\r\nHost: example.test\r\n\r\nrefresh=${refresh}", 3600,
                Arrays.asList(
                    new SessionProfile.Rule("session", SessionProfile.Source.COOKIE, "session", name, SessionProfile.Destination.COOKIE, "session"),
                    new SessionProfile.Rule("token", SessionProfile.Source.JSON, "data.access_token", "old-token", SessionProfile.Destination.HEADER, "Authorization", "Bearer "),
                    new SessionProfile.Rule("refresh", SessionProfile.Source.JSON, "refresh_token", "seed-" + name, SessionProfile.Destination.VARIABLE, "")), enabled, automatic);
    }
    private static void workflow() throws Exception {
        Fixture f = new Fixture(); SessionProfiles manager = new SessionProfiles(f.extension);
        java.nio.file.Path file = java.nio.file.Files.createTempFile("workflow", ".json");
        try {
            // The whole origin is in scope, so the login bypass below is tested on an in-scope URL.
            SessionProfile p = withScope("workflow", Collections.singletonList(ScopeRule.include(new URL("https://example.test/"))), false, false, false);
            p.configureWorkflow("POST /login HTTP/1.1\r\nHost: example.test\r\n\r\nuser=alice", new URL("https://example.test/login"));
            assert p.matches(new URL("https://example.test/login"), u -> false);
            manager.save(p, null); manager.test(p.name);
            await(() -> p.lastSuccess != null);
            assert f.sentRequests.peek().startsWith("POST /login");
            java.time.Instant first = p.lastSuccess;
            await(() -> { manager.test(p.name); return !p.lastSuccess.equals(first); });
            assert f.sentRequests.stream().anyMatch(r -> r.startsWith("POST /refresh") && r.endsWith("refresh=rotated"));
            f.responseText = NO_MATCH;
            await(() -> { if (!p.status.startsWith("Failed")) manager.test(p.name); return p.status.startsWith("Failed"); });
            assert p.status.contains("next attempt logs in");
            f.responseText = RESPONSE; f.sentRequests.clear();
            java.time.Instant failedAfter = p.lastSuccess;
            await(() -> { manager.test(p.name); return !p.lastSuccess.equals(failedAfter); });
            assert f.sentRequests.peek().startsWith("POST /login") : "A failed refresh must fall back to login";
            f.sentRequests.clear(); java.time.Instant relogged = p.lastSuccess;
            await(() -> { manager.test(p.name); return !p.lastSuccess.equals(relogged); });
            assert f.sentRequests.peek().startsWith("POST /refresh") : "After a successful login, refresh resumes";
            manager.setEnabled(p.name, true);
            IHttpRequestResponse ownLogin = f.message("POST /login HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: workflow\r\n\r\nuser=alice");
            assert manager.process(true, ownLogin);
            assert !string(ownLogin.getRequest()).contains("Authorization:") : "Login requests must bypass injection";
            assert !manager.getDebugLog().snapshot().stream().anyMatch(e -> e.kind.equals("Routing")) : "Unmatched traffic is not logged by default";
            assert !manager.process(true, f.message("GET /elsewhere HTTP/1.1\r\nHost: example.test\r\n\r\n"));
            assert !manager.getDebugLog().snapshot().stream().anyMatch(e -> e.kind.equals("Routing"));
            manager.setLogUnmatched(true);
            assert !manager.process(true, f.message("GET /elsewhere HTTP/1.1\r\nHost: example.test\r\n\r\n"));
            assert latest(manager).kind.equals("Routing");
            try {
                profile("placeholder", false, false).configureWorkflow("POST /login HTTP/1.1\r\nHost: example.test\r\n\r\nuser=${missing}",
                        new URL("https://example.test/login"));
                throw new AssertionError("Unknown login placeholder accepted");
            } catch (IllegalArgumentException expected) { assert expected.getMessage().contains("missing"); }
            ProfileStore.save(file, Arrays.asList(p));
            SessionProfile restored = ProfileStore.load(file).get(0);
            assert restored.loginRequest.equals(p.loginRequest) && restored.loginEndpoint.equals(p.loginEndpoint);
            assert restored.scope.equals(p.scope);
        } finally { manager.extensionUnloaded(); java.nio.file.Files.deleteIfExists(file); }
    }
    private static SessionProfile withScope(String name, List<ScopeRule> scope, boolean burpScope, boolean enabled, boolean automatic) throws Exception {
        SessionProfile p = profile(name, false, false);
        return new SessionProfile(name, p.endpoint, scope, burpScope, p.request, p.interval, p.rules, enabled, automatic, ReauthHttpClient.Protocol.AUTO);
    }
    private static URL url(String path) throws Exception { return new URL("https://example.test" + path); }
    private static void scope() throws Exception {
        java.util.function.Predicate<URL> outside = u -> false, inside = u -> true;
        List<ScopeRule> rules = Arrays.asList(
                new ScopeRule(ScopeRule.Action.INCLUDE, ScopeRule.Match.EXACT, url("/one")),
                new ScopeRule(ScopeRule.Action.INCLUDE, ScopeRule.Match.PREFIX, url("/api")),
                new ScopeRule(ScopeRule.Action.EXCLUDE, ScopeRule.Match.PREFIX, url("/api/logout")));
        SessionProfile p = withScope("scoped", rules, false, false, true);
        assert p.matches(url("/one"), outside) && p.matches(url("/one?page=2"), outside) : "EXACT compares the path, not the query";
        assert !p.matches(url("/one/child"), outside);
        assert p.matches(url("/api"), outside) && p.matches(url("/api/users"), outside) && !p.matches(url("/apievil"), outside);
        assert !p.matches(url("/api/logout"), outside) && !p.matches(url("/api/logout/all"), outside) : "Exclusions win over inclusions";
        assert p.matches(url("/api/logoutx"), outside) : "Exclusions also match on path boundaries";
        assert !p.matches(new URL("https://other.test/api"), outside) && !p.matches(new URL("http://example.test/api"), outside);
        assert !p.matches(url("/api/../admin"), inside) && !p.matches(url("/api/%2E%2e/admin"), inside);
        assert p.describeScope().equals("exactly https://example.test/one (+1), 1 exclusion");
        try { withScope("excludes-only", rules.subList(2, 3), false, false, true); throw new AssertionError("Profile without an include accepted"); }
        catch (IllegalArgumentException expected) { assert expected.getMessage().contains("Burp target scope"); }
        try { new ScopeRule(ScopeRule.Action.INCLUDE, ScopeRule.Match.PREFIX, new URL("ftp://example.test/")); throw new AssertionError("FTP scope accepted"); }
        catch (IllegalArgumentException expected) { }
        SessionProfile burp = withScope("burp", rules.subList(2, 3), true, false, true);
        assert burp.matches(url("/anything"), inside) && !burp.matches(url("/anything"), outside);
        assert !burp.matches(url("/api/logout"), inside) : "Exclusions also apply to Burp's target scope";
        assert burp.describeScope().equals("Burp target scope, 1 exclusion");

        Fixture f = new Fixture(); f.burpScope.add("https://example.test/in"); SessionProfiles manager = new SessionProfiles(f.extension);
        java.nio.file.Path file = java.nio.file.Files.createTempFile("scope", ".json");
        try {
            SessionProfile routed = withScope("routed", Collections.emptyList(), true, true, true);
            manager.save(routed, null);
            await(() -> routed.lastSuccess != null);
            IHttpRequestResponse in = f.message("GET /in/page HTTP/1.1\r\nHost: example.test\r\n\r\n");
            assert manager.process(true, in) && string(in.getRequest()).contains("Authorization: Bearer new-token") : "Burp target scope routes requests";
            IHttpRequestResponse out = f.message("GET /out HTTP/1.1\r\nHost: example.test\r\n\r\n");
            assert !manager.process(true, out) && !string(out.getRequest()).contains("Authorization:");

            ProfileStore.save(file, Arrays.asList(p, burp));
            List<SessionProfile> restored = ProfileStore.load(file);
            assert restored.get(0).scope.equals(rules) && !restored.get(0).burpScope;
            assert restored.get(1).scope.equals(rules.subList(2, 3)) && restored.get(1).burpScope;
            assert java.nio.file.Files.readString(file).contains("\"schemaVersion\": 2");

            // Version 1 files: a plain scope URL, or EXACT/SUBTREE lines that replace it.
            com.google.gson.JsonObject v1 = com.google.gson.JsonParser.parseString(java.nio.file.Files.readString(file)).getAsJsonObject();
            v1.addProperty("schemaVersion", 1);
            com.google.gson.JsonArray old = v1.getAsJsonArray("profiles");
            old.get(0).getAsJsonObject().addProperty("scope", "https://example.test/api");
            old.get(1).getAsJsonObject().addProperty("scope", "https://example.test/ignored");
            old.get(1).getAsJsonObject().addProperty("scopeRules", "EXACT https://example.test/one\nSUBTREE https://example.test/two\n");
            old.forEach(profile -> profile.getAsJsonObject().remove("burpScope"));
            java.nio.file.Files.writeString(file, v1.toString());
            List<SessionProfile> migrated = ProfileStore.load(file);
            assert migrated.get(0).scope.equals(Collections.singletonList(ScopeRule.include(url("/api")))) && !migrated.get(0).burpScope;
            assert migrated.get(1).scope.equals(Arrays.asList(new ScopeRule(ScopeRule.Action.INCLUDE, ScopeRule.Match.EXACT, url("/one")),
                    new ScopeRule(ScopeRule.Action.INCLUDE, ScopeRule.Match.PREFIX, url("/two")))) && !migrated.get(1).burpScope;
            old.get(0).getAsJsonObject().addProperty("scopeRules", "INCLUDE https://example.test/");
            java.nio.file.Files.writeString(file, v1.toString());
            try { ProfileStore.load(file); throw new AssertionError("Invalid version 1 rule accepted"); }
            catch (java.io.IOException expected) { }
        } finally { manager.extensionUnloaded(); java.nio.file.Files.deleteIfExists(file); }
    }
    private static void extraction() throws Exception {
        SessionProfile alice = profile("alice", true, true), bob = profile("bob", true, true);
        alice.accept(RESPONSE);
        assert alice.render().endsWith("refresh=rotated");
        assert bob.render().endsWith("refresh=seed-bob");
        bob.accept(RESPONSE.replace("refresh_token", "missing").replace("new-token", "partial-token"));
        assert bob.snapshot().get("token").equals("partial-token") && bob.snapshot().get("refresh").equals("seed-bob")
                : "A response without a rule's field keeps that value (non-rotating refresh tokens, login vs refresh fields)";
        Map<String, String> before = alice.snapshot();
        try { alice.accept(NO_MATCH); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { assert alice.snapshot() == before; }
        try { alice.accept(RESPONSE.replace("rotated", "a\\r\\nX-Injected: 1")); throw new AssertionError("CR/LF variable accepted"); }
        catch (IllegalArgumentException expected) { assert alice.snapshot() == before : "Unsafe values must not be rendered into renewals"; }
        assert new SessionProfile.Rule("csrf", SessionProfile.Source.HEADER, "x-csrf", "", SessionProfile.Destination.VARIABLE, "").extract(RESPONSE).equals("csrf-value");
        assert new SessionProfile.Rule("refresh", SessionProfile.Source.REGEX, "\"refresh_token\":\"([^\"]+)\"", "", SessionProfile.Destination.VARIABLE, "").extract(RESPONSE).equals("rotated");
    }
    private static void routing() throws Exception {
        Fixture f = new Fixture(); SessionProfiles profiles = new SessionProfiles(f.extension);
        try {
            SessionProfile alice = profile("alice", true, false), bob = profile("bob", true, false);
            profiles.save(alice, null); profiles.save(bob, null);
            await(() -> alice.lastSuccess != null && bob.lastSuccess != null);
            Map<String, String> successful = alice.snapshot();
            f.responseText = NO_MATCH;
            // Publication can precede release of the renewal lock. Retry submission
            // until the failure check runs rather than assuming the worker is idle.
            await(() -> {
                if (!alice.status.startsWith("Failed")) profiles.test("alice");
                return alice.status.startsWith("Failed");
            });
            assert alice.snapshot() == successful : "Failed renewals must keep the entire previous snapshot";
            assert bob.status.startsWith("Ready") : "Another profile's failure must remain isolated";
            f.responseText = RESPONSE;
            IHttpRequestResponse marked = f.message("GET /api/users HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: alice\r\nCookie: unrelated=keep; session=stale\r\nAuthorization: old\r\n\r\n");
            assert profiles.process(true, marked);
            String rendered = string(marked.getRequest());
            assert !rendered.contains("X-Reauth-Profile");
            assert rendered.contains("Authorization: Bearer new-token");
            assert rendered.contains("unrelated=keep; session=new-cookie");
            RequestDebugLog.Event changed = latest(profiles);
            assert changed.changed && changed.profile.equals("alice");
            assert changed.before.contains("Authorization: old");
            assert changed.after.contains("Authorization: Bearer new-token");
            assert changed.details.contains("Removed: X-Reauth-Profile: alice");
            assert changed.details.contains("Added: Authorization: Bearer new-token");
            assert changed.reason.contains("marker");
            IHttpRequestResponse unmarked = f.message("GET /api/users HTTP/1.1\r\nHost: example.test\r\n\r\n");
            assert !profiles.process(true, unmarked) : "Marker profiles must not modify unmarked traffic";
            assert !string(unmarked.getRequest()).contains("Authorization:");
            SessionProfile scopeAlice = profile("scope-alice", true, true), scopeBob = profile("scope-bob", true, true);
            profiles.save(scopeAlice, null); profiles.save(scopeBob, null);
            await(() -> scopeAlice.lastSuccess != null && scopeBob.lastSuccess != null);
            IHttpRequestResponse markedScope = f.message("GET /api/users HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: scope-alice\r\n\r\n");
            assert profiles.process(true, markedScope);
            assert !string(markedScope.getRequest()).contains("Authorization:") : "Scope profiles must not be selected by marker";
            assert latest(profiles).reason.contains("Scope mode");
            IHttpRequestResponse conflict = f.message("GET /api/users HTTP/1.1\r\nHost: example.test\r\n\r\n");
            assert profiles.process(true, conflict);
            assert !string(conflict.getRequest()).contains("Authorization:");
            assert !latest(profiles).changed && latest(profiles).reason.contains("Ambiguous");
            IHttpRequestResponse unknown = f.message("GET /api/users HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: unknown\r\n\r\n");
            assert profiles.process(true, unknown);
            assert !string(unknown.getRequest()).contains("X-Reauth-Profile");
            assert !string(unknown.getRequest()).contains("Authorization:");
            assert latest(profiles).changed && latest(profiles).reason.contains("Unknown");
            IHttpRequestResponse outside = f.message("GET /outside HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: alice\r\n\r\n");
            assert profiles.process(true, outside);
            assert !string(outside.getRequest()).contains("Authorization:");
            profiles.remove("scope-bob");
            assert profiles.process(true, conflict);
            assert string(conflict.getRequest()).contains("Authorization: Bearer new-token");
            assert latest(profiles).reason.contains("scope");
            assert profiles.process(true, conflict);
            assert !latest(profiles).changed : "Already-correct credentials should report no change";
            assert profiles.getDebugLog().snapshot().stream().anyMatch(event -> event.kind.equals("Renewal")
                    && event.details.contains("new-token") && event.response.equals(RESPONSE) && !event.changed);
            profiles.remove("alice"); profiles.remove("bob"); profiles.remove("scope-alice");
            assert !profiles.process(true, f.message("GET /api HTTP/1.1\r\nHost: example.test\r\n\r\n"));
        } finally { profiles.extensionUnloaded(); }
    }
    private static void concurrency() throws Exception {
        Fixture f = new Fixture(); f.started = new CountDownLatch(2); f.release = new CountDownLatch(1);
        SessionProfiles profiles = new SessionProfiles(f.extension);
        try {
            SessionProfile alice = differentRenewalPath("alice"), bob = differentRenewalPath("bob");
            profiles.save(alice, null); profiles.save(bob, null);
            profiles.test("alice"); profiles.test("bob");
            assert f.started.await(3, TimeUnit.SECONDS) : "Profiles must renew concurrently";
            assert profiles.process(true, f.message(f.sentRequests.peek())) : "Renewal traffic must bypass injection even on another listener thread and a custom path";
            assert profiles.process(true, f.message(f.sentRequests.peek().replace("HTTP/1.1", "HTTP/2")))
                    : "Burp's negotiated protocol representation must not break renewal isolation";
            profiles.test("alice");
            // Probe another worker to ensure the duplicate renewal task had time to run.
            profiles.test("bob");
            assert f.maxConcurrent.get() == 2;
            profiles.remove("alice");
            f.release.countDown();
            await(() -> bob.lastSuccess != null);
            assert alice.lastSuccess == null : "Deleted profile must not publish an in-flight result";
            assert f.calls.get() == 2 : "A profile must not overlap its own renewals";
        } finally { f.release.countDown(); profiles.extensionUnloaded(); }
    }
    private static void protocols() throws Exception {
        Fixture f = new Fixture();
        com.nccgroup.jwtreauth.ui.ProfileRequestEditor editor = new com.nccgroup.jwtreauth.ui.ProfileRequestEditor(
                f.callbacks, () -> "https://example.test/login", bytes("POST /login HTTP/1.1\r\nHost: example.test\r\n\r\n"));
        assert editor.getHttpService() != null && editor.getRequest().length > 0 && editor.getResponse() != null;
        assert f.editors.get(0).controller == editor;
        ReauthHttpClient client = new ReauthHttpClient(f.callbacks);
        byte[] request = bytes("POST /refresh?q=1 HTTP/2\r\nHost: virtual.test:8443\r\nConnection: keep-alive, X-Hop\r\nX-Hop: discard\r\nCookie: session=seed; csrf=first==; duplicate=one\r\ncookie: duplicate=two; empty=; quoted=\"a=b\"\r\nContent-Length: 999\r\n\r\ntoken=seed");
        ReauthHttpClient.Prepared h2 = client.prepare(f.service, request, ReauthHttpClient.Protocol.AUTO);
        assert h2.http2;
        List<String> pseudoOrder = new ArrayList<>();
        h2.headers.stream().filter(h -> h.getName().startsWith(":" )).forEach(h -> pseudoOrder.add(h.getName()));
        assert pseudoOrder.equals(Arrays.asList(":scheme", ":method", ":path", ":authority"))
                : "Burp marks valid-but-reordered scheme/method pseudo-headers as kettled";
        Map<String, String> headers = new HashMap<>(); h2.headers.forEach(h -> headers.put(h.getName(), h.getValue()));
        assert headers.get(":method").equals("POST");
        assert headers.get(":path").equals("/refresh?q=1");
        assert headers.get(":scheme").equals("https");
        assert headers.get(":authority").equals("virtual.test:8443");
        assert headers.get("content-length").equals("10");
        assert !headers.containsKey("connection") && !headers.containsKey("x-hop") && !headers.containsKey("host");
        List<String> crumbs = new ArrayList<>();
        h2.headers.stream().filter(h -> h.getName().equals("cookie")).forEach(h -> crumbs.add(h.getValue()));
        assert crumbs.equals(Arrays.asList("session=seed", "csrf=first==", "duplicate=one", "duplicate=two", "empty=", "quoted=\"a=b\""));
        assert h2.headers.stream().filter(h -> h.getName().equals("cookie")).noneMatch(h -> h.getValue().contains("; "));
        assert string(client.send(f.service, h2)).equals(RESPONSE) && f.http2Calls.get() == 1;
        ReauthHttpClient.Prepared spaced = client.prepare(f.service,
                bytes("GET / HTTP/2\r\nHost: example.test\r\nX-Test : value\r\n\r\n"), ReauthHttpClient.Protocol.HTTP_2);
        assert spaced.headers.stream().anyMatch(h -> h.getName().equals("x-test") && h.getValue().equals("value"));
        for (String invalid : Arrays.asList("X Invalid: value", "X-Test: bad\u0000value", "X-Test: bad\nvalue")) {
            try {
                client.prepare(f.service, bytes("GET / HTTP/2\r\nHost: example.test\r\n" + invalid + "\r\n\r\n"), ReauthHttpClient.Protocol.HTTP_2);
                throw new AssertionError("Invalid header accepted");
            } catch (IllegalArgumentException expected) { }
        }
        ReauthHttpClient.Prepared automatic = client.prepare(f.service, bytes("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), ReauthHttpClient.Protocol.AUTO);
        assert !automatic.http2 && !automatic.forceHttp1;
        client.send(f.service, automatic); assert Boolean.FALSE.equals(f.lastForceHttp1);
        ReauthHttpClient.Prepared h1 = client.prepare(f.service, request, ReauthHttpClient.Protocol.HTTP_1);
        assert !h1.http2 && h1.forceHttp1 && string(h1.request).startsWith("POST /refresh?q=1 HTTP/1.1");
        client.send(f.service, h1); assert Boolean.TRUE.equals(f.lastForceHttp1);
        assert client.prepare(f.service, bytes("GET / HTTP/1.0\r\n\r\n"), ReauthHttpClient.Protocol.AUTO).forceHttp1;
        ReauthHttpClient.Prepared forced = client.prepare(f.service, bytes("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n"), ReauthHttpClient.Protocol.HTTP_2);
        assert string(forced.body).equals("test");
        for (String version : Arrays.asList("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0")) {
            SessionProfile p = profile("version", false, false);
            new SessionProfile(p.name, p.endpoint, p.scope, false, p.request.replace("HTTP/1.1", version), p.interval, p.rules, false, false, ReauthHttpClient.Protocol.AUTO);
        }
        SessionProfiles profiles = new SessionProfiles(f.extension);
        try {
            SessionProfile p = profile("http2", false, false);
            SessionProfile h2Profile = new SessionProfile(p.name, p.endpoint, p.scope, false, p.request.replace("HTTP/1.1", "HTTP/2"), p.interval, p.rules, false, false, ReauthHttpClient.Protocol.AUTO);
            f.http2Listener = profiles;
            profiles.save(h2Profile, null); profiles.test(h2Profile.name);
            await(() -> h2Profile.lastSuccess != null);
            assert h2Profile.snapshot().get("token").equals("new-token");
            assert h2Profile.render().endsWith("refresh=rotated");
        } finally { profiles.extensionUnloaded(); }
    }
    private static void persistence() throws Exception {
        java.nio.file.Path directory = java.nio.file.Files.createTempDirectory("jwt-profiles-test-");
        java.nio.file.Path file = directory.resolve("profiles.json");
        Fixture fixture = new Fixture(); SessionProfiles manager = new SessionProfiles(fixture.extension);
        try {
            SessionProfile seed = profile("saved", false, true);
            SessionProfile original = new SessionProfile(seed.name, seed.endpoint, seed.scope, false,
                    seed.request.replace("HTTP/1.1", "HTTP/2"), seed.interval, seed.rules, true, true, ReauthHttpClient.Protocol.HTTP_2);
            original.accept(RESPONSE);
            ProfileStore.save(file, Arrays.asList(original, profile("other", false, false)));
            List<SessionProfile> restored = ProfileStore.load(file);
            assert restored.size() == 2;
            SessionProfile p = restored.get(0);
            assert p.name.equals(original.name) && p.endpoint.equals(original.endpoint) && p.scope.equals(original.scope);
            assert p.request.equals(original.request) && p.interval == original.interval && p.autoMatch && p.enabled;
            assert p.protocol == ReauthHttpClient.Protocol.HTTP_2;
            assert p.rules.size() == 3 && p.rules.get(1).prefix.equals("Bearer ");
            assert p.rules.get(0).source == SessionProfile.Source.COOKIE;
            assert p.rules.get(1).destination == SessionProfile.Destination.HEADER;
            assert p.rules.get(0).initial.equals("saved");
            assert p.snapshot().equals(original.snapshot()) && p.render().endsWith("refresh=rotated");
            assert p.lastSuccess == null : "Restored credentials require renewal before injection";
            manager.save(profile("untouched", false, false), null);
            manager.save(profile("saved", false, false), null);
            manager.loadProfiles(restored);
            await(() -> p.lastSuccess != null);
            assert manager.list().size() == 3;
            assert manager.list().stream().filter(v -> v.name.equals("saved")).findFirst().get().snapshot().get("refresh").equals("rotated");
            String json = java.nio.file.Files.readString(file);
            java.nio.file.Files.writeString(file, json.replace("\"schemaVersion\": 2", "\"schemaVersion\": 99"));
            try { ProfileStore.load(file); throw new AssertionError("Unknown schema accepted"); }
            catch (java.io.IOException expected) { }
            java.nio.file.Files.writeString(file, json.replace("\"interval\": 3600", "\"interval\": 0"));
            try { manager.loadProfiles(ProfileStore.load(file)); throw new AssertionError("Invalid profile accepted"); }
            catch (java.io.IOException expected) { assert manager.list().size() == 3; }
            java.nio.file.Files.writeString(file, json.replace("\"HTTP_2\"", "\"UNKNOWN\""));
            try { ProfileStore.load(file); throw new AssertionError("Invalid protocol accepted"); }
            catch (java.io.IOException expected) { }
            java.nio.file.Files.writeString(file, "{broken");
            try { ProfileStore.load(file); throw new AssertionError("Malformed file accepted"); }
            catch (java.io.IOException expected) { }
            ProfileStore.save(file, java.util.Collections.emptyList());
            assert ProfileStore.load(file).isEmpty();
        } finally {
            manager.extensionUnloaded(); java.nio.file.Files.deleteIfExists(file); java.nio.file.Files.deleteIfExists(directory);
        }
    }
    private static RequestDebugLog.Event latest(SessionProfiles profiles) {
        List<RequestDebugLog.Event> events = profiles.getDebugLog().snapshot();
        return events.stream().filter(event -> event.kind.equals("Request") || event.kind.equals("Routing"))
                .reduce((previous, current) -> current).orElseThrow(AssertionError::new);
    }
    private static void debugHistory() {
        RequestDebugLog log = new RequestDebugLog();
        for (int i = 0; i < RequestDebugLog.MAX_EVENTS + 20; i++)
            log.add("Request", "alice", "https://example.test/", "Test", "old", "new", "");
        assert log.snapshot().size() == RequestDebugLog.MAX_EVENTS;
        assert log.snapshot().get(0).id == 21;
        log.add("Request", "alice", "", "Long request", "x".repeat(RequestDebugLog.MAX_TEXT + 1), "x".repeat(RequestDebugLog.MAX_TEXT) + "y", "");
        RequestDebugLog.Event event = log.snapshot().get(RequestDebugLog.MAX_EVENTS - 1);
        assert event.changed : "Compare full requests before truncating the display";
        assert event.before.contains("Display truncated");
        log.clear(); assert log.snapshot().isEmpty();
    }
    private static SessionProfile differentRenewalPath(String name) throws Exception {
        SessionProfile p = profile(name, false, false);
        return new SessionProfile(p.name, p.endpoint, p.scope, false, p.request.replace("/refresh", "/rotate"),
                p.interval, p.rules, false, false, ReauthHttpClient.Protocol.AUTO);
    }
    private interface Check { boolean ok(); }
    private static void await(Check check) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
        while (!check.ok() && System.nanoTime() < deadline) Thread.sleep(10);
        assert check.ok() : "Timed out";
    }
    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, InvocationHandler handler) { return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler); }
    private static byte[] bytes(String s) { return s.getBytes(StandardCharsets.ISO_8859_1); }
    private static String string(byte[] bytes) { return new String(bytes, StandardCharsets.ISO_8859_1); }
    private static final class EditorDouble {
        final IMessageEditorController controller;
        final boolean editable;
        volatile byte[] message;
        volatile boolean isRequest;
        final javax.swing.JPanel component = new javax.swing.JPanel();
        EditorDouble(IMessageEditorController controller, boolean editable) { this.controller = controller; this.editable = editable; }
        IMessageEditor editor() {
            return proxy(IMessageEditor.class, (p, method, args) -> {
                switch (method.getName()) {
                    case "getComponent": return component;
                    case "setMessage":
                        if (args[0] == null) throw new NullPointerException("Message cannot be null");
                        isRequest = (Boolean)args[1]; message = ((byte[])args[0]).clone(); return null;
                    case "getMessage": return message;
                    case "isMessageModified": return false;
                    default: return null;
                }
            });
        }
    }
    private static final class Fixture {
        final List<EditorDouble> editors = new CopyOnWriteArrayList<>();
        final List<IExtensionStateListener> listeners = new CopyOnWriteArrayList<>();
        final ConcurrentLinkedQueue<String> sentRequests = new ConcurrentLinkedQueue<>();
        final AtomicInteger calls = new AtomicInteger(), concurrent = new AtomicInteger(), maxConcurrent = new AtomicInteger();
        final AtomicInteger http2Calls = new AtomicInteger();
        volatile Boolean lastForceHttp1;
        volatile SessionProfiles http2Listener;
        volatile CountDownLatch started, release;
        volatile String responseText = RESPONSE;
        final List<String> burpScope = new CopyOnWriteArrayList<>();
        final IHttpService service = proxy(IHttpService.class, (p, m, a) -> {
            switch (m.getName()) { case "getHost": return "example.test"; case "getPort": return 443; case "getProtocol": return "https"; default: return null; }
        });
        final IExtensionHelpers helpers = proxy(IExtensionHelpers.class, (p, m, a) -> {
            switch (m.getName()) {
                case "stringToBytes": return bytes((String)a[0]);
                case "bytesToString": return string((byte[])a[0]);
                case "buildHttpService": return service;
                case "buildHeader": return proxy(IHttpHeader.class, (q, method, args) -> method.getName().equals("getName") ? a[0] : a[1]);
                case "analyzeResponse": return proxy(IResponseInfo.class, (q, method, args) -> method.getName().equals("getStatusCode") ? (short)200 : null);
                case "analyzeRequest": {
                    byte[] raw = a[0] instanceof byte[] ? (byte[])a[0] : ((IHttpRequestResponse)a[0]).getRequest();
                    String text = string(raw); int offset = text.indexOf("\r\n\r\n") + 4;
                    List<String> headers = Arrays.asList(text.substring(0, offset - 4).split("\r\n"));
                    return proxy(IRequestInfo.class, (q, method, args) -> {
                        switch (method.getName()) { case "getBodyOffset": return offset; case "getHeaders": return headers;
                            case "getUrl": return new URL("https://example.test" + headers.get(0).split(" ")[1]); default: return null; }
                    });
                }
                case "buildHttpMessage": {
                    @SuppressWarnings("unchecked") List<String> headers = new ArrayList<>((List<String>)a[0]);
                    byte[] body = (byte[])a[1];
                    headers.removeIf(h -> h.toLowerCase(Locale.ROOT).startsWith("content-length:"));
                    if (body.length > 0) headers.add("Content-Length: " + body.length);
                    return bytes(String.join("\r\n", headers) + "\r\n\r\n" + string(body));
                }
                default: return null;
            }
        });
        final IBurpExtenderCallbacks callbacks = proxy(IBurpExtenderCallbacks.class, (p, m, a) -> {
            if (m.getName().equals("getHelpers")) return helpers;
            if (m.getName().equals("isInScope")) return burpScope.stream().anyMatch(prefix -> a[0].toString().startsWith(prefix));
            if (m.getName().equals("createMessageEditor")) {
                EditorDouble editor = new EditorDouble((IMessageEditorController)a[0], (Boolean)a[1]);
                editors.add(editor); return editor.editor();
            }
            if (m.getName().equals("registerExtensionStateListener")) { listeners.add((IExtensionStateListener)a[0]); return null; }
            if (m.getName().equals("makeHttp2Request")) {
                assert a.length == 4 && Boolean.TRUE.equals(a[3]);
                @SuppressWarnings("unchecked") List<IHttpHeader> fields = (List<IHttpHeader>)a[1];
                for (IHttpHeader field : fields) {
                    assert field.getName().startsWith(":") || field.getName().matches("[!#$%&'*+.^_`|~0-9a-z-]+") : "Header cannot be represented normally";
                    assert !field.getName().equals("cookie") || !field.getValue().contains("; ") : "Combined cookie field would kettle the request";
                }
                if (http2Listener != null) {
                    List<String> before = new ArrayList<>(); fields.forEach(h -> before.add(h.getName() + "=" + h.getValue()));
                    IHttpRequestResponse nativeMessage = proxy(IHttpRequestResponse.class, (q, method, args) -> {
                        throw new AssertionError("Native HTTP/2 renewal must bypass all legacy message access: " + method.getName());
                    });
                    assert http2Listener.process(true, nativeMessage);
                    List<String> after = new ArrayList<>(); fields.forEach(h -> after.add(h.getName() + "=" + h.getValue()));
                    assert before.equals(after) : "Renewal pseudo-headers must remain untouched";
                }
                assert fields.stream().filter(h -> h.getName().equals(":method")).count() == 1;
                if (fields.stream().noneMatch(h -> h.getName().equals(":method") && h.getValue().equals("CONNECT"))) {
                    assert fields.stream().filter(h -> h.getName().equals(":scheme")).count() == 1;
                    List<String> order = new ArrayList<>();
                    fields.stream().filter(h -> h.getName().startsWith(":" )).forEach(h -> order.add(h.getName()));
                    assert order.equals(Arrays.asList(":scheme", ":method", ":path", ":authority"));
                }
                http2Calls.incrementAndGet(); return bytes(responseText);
            }
            if (!m.getName().equals("makeHttpRequest")) return null;
            if (a.length == 3) lastForceHttp1 = (Boolean)a[2];
            sentRequests.add(string((byte[])a[1]));
            calls.incrementAndGet(); int count = concurrent.incrementAndGet(); maxConcurrent.accumulateAndGet(count, Math::max);
            try {
                if (started != null) started.countDown();
                if (release != null && !release.await(4, TimeUnit.SECONDS)) throw new AssertionError("Blocked renewal");
                return message(string((byte[])a[1]));
            } finally { concurrent.decrementAndGet(); }
        });
        final JWTReauth extension = new JWTReauth() {
            final LogController log = new LogController();
            @Override public IBurpExtenderCallbacks getCallbacks() { return callbacks; }
            @Override public LogController getLogController() { return log; }
        };
        IHttpRequestResponse message(String request) {
            final byte[][] data = {bytes(request), bytes(responseText)};
            return proxy(IHttpRequestResponse.class, (p, m, a) -> {
                switch (m.getName()) { case "getRequest": return data[0]; case "setRequest": data[0] = (byte[])a[0]; return null;
                    case "getResponse": return data[1]; case "getHttpService": return service; default: return null; }
            });
        }
    }
}
