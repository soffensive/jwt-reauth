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
    public static void main(String[] args) throws Exception {
        extraction(); routing(); concurrency(); startup();
        System.out.println("Session profile extraction, routing, and concurrency tests passed");
    }
    private static void startup() throws Exception {
        Fixture fixture = new Fixture();
        JWTReauth extension = new JWTReauth();
        try {
            javax.swing.SwingUtilities.invokeAndWait(() -> extension.registerExtenderCallbacks(fixture.callbacks));
            assert extension.getSessionProfiles() != null;
            assert extension.getSessionProfilesPanel() != null;
        } finally {
            if (extension.getSessionProfiles() != null) extension.getSessionProfiles().extensionUnloaded();
            if (extension.getSessionProfilesPanel() != null) extension.getSessionProfilesPanel().extensionUnloaded();
            if (extension.getTokenListener() != null) extension.getTokenListener().extensionUnloaded();
            if (extension.getTokenListenerStatePanel() != null) extension.getTokenListenerStatePanel().extensionUnloaded();
        }
    }
    private static SessionProfile profile(String name, boolean enabled, boolean automatic) throws Exception {
        return new SessionProfile(name, new URL("https://example.test/refresh"), new URL("https://example.test/api"),
                "POST /refresh HTTP/1.1\r\nHost: example.test\r\n\r\nrefresh=${refresh}", 3600,
                Arrays.asList(
                    new SessionProfile.Rule("session", SessionProfile.Source.COOKIE, "session", name, SessionProfile.Destination.COOKIE, "session"),
                    new SessionProfile.Rule("token", SessionProfile.Source.JSON, "data.access_token", "old-token", SessionProfile.Destination.HEADER, "Authorization", "Bearer "),
                    new SessionProfile.Rule("refresh", SessionProfile.Source.JSON, "refresh_token", "seed-" + name, SessionProfile.Destination.VARIABLE, "")), enabled, automatic);
    }
    private static void extraction() throws Exception {
        SessionProfile alice = profile("alice", true, true), bob = profile("bob", true, true);
        alice.accept(RESPONSE);
        assert alice.render().endsWith("refresh=rotated");
        assert bob.render().endsWith("refresh=seed-bob");
        Map<String, String> before = alice.snapshot();
        try { alice.accept(RESPONSE.replace("refresh_token", "missing")); throw new AssertionError(); }
        catch (IllegalArgumentException expected) { assert alice.snapshot() == before; }
        assert new SessionProfile.Rule("csrf", SessionProfile.Source.HEADER, "x-csrf", "", SessionProfile.Destination.VARIABLE, "").extract(RESPONSE).equals("csrf-value");
        assert new SessionProfile.Rule("refresh", SessionProfile.Source.REGEX, "\"refresh_token\":\"([^\"]+)\"", "", SessionProfile.Destination.VARIABLE, "").extract(RESPONSE).equals("rotated");
        assert alice.matches(new URL("https://example.test/api/users"));
        assert !alice.matches(new URL("https://example.test/apievil"));
        assert !alice.matches(new URL("https://other.test/api"));
    }
    private static void routing() throws Exception {
        Fixture f = new Fixture(); SessionProfiles profiles = new SessionProfiles(f.extension);
        try {
            SessionProfile alice = profile("alice", true, true), bob = profile("bob", true, true);
            profiles.save(alice, null); profiles.save(bob, null);
            await(() -> alice.lastSuccess != null && bob.lastSuccess != null);
            Map<String, String> successful = alice.snapshot();
            f.responseText = RESPONSE.replace("refresh_token", "missing");
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
            IHttpRequestResponse conflict = f.message("GET /api/users HTTP/1.1\r\nHost: example.test\r\n\r\n");
            assert profiles.process(true, conflict);
            assert !string(conflict.getRequest()).contains("Authorization:");
            IHttpRequestResponse unknown = f.message("GET /api/users HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: unknown\r\n\r\n");
            assert profiles.process(true, unknown);
            assert !string(unknown.getRequest()).contains("X-Reauth-Profile");
            assert !string(unknown.getRequest()).contains("Authorization:");
            IHttpRequestResponse outside = f.message("GET /outside HTTP/1.1\r\nHost: example.test\r\nX-Reauth-Profile: alice\r\n\r\n");
            assert profiles.process(true, outside);
            assert !string(outside.getRequest()).contains("Authorization:");
            profiles.remove("bob");
            assert profiles.process(true, conflict);
            assert string(conflict.getRequest()).contains("Authorization: Bearer new-token");
            profiles.remove("alice");
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
    private static SessionProfile differentRenewalPath(String name) throws Exception {
        SessionProfile p = profile(name, false, false);
        return new SessionProfile(p.name, p.endpoint, p.scope, p.request.replace("/refresh", "/rotate"),
                p.interval, p.rules, false, false);
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
    private static final class Fixture {
        final ConcurrentLinkedQueue<String> sentRequests = new ConcurrentLinkedQueue<>();
        final AtomicInteger calls = new AtomicInteger(), concurrent = new AtomicInteger(), maxConcurrent = new AtomicInteger();
        volatile CountDownLatch started, release;
        volatile String responseText = RESPONSE;
        final IHttpService service = proxy(IHttpService.class, (p, m, a) -> {
            switch (m.getName()) { case "getHost": return "example.test"; case "getPort": return 443; case "getProtocol": return "https"; default: return null; }
        });
        final IExtensionHelpers helpers = proxy(IExtensionHelpers.class, (p, m, a) -> {
            switch (m.getName()) {
                case "stringToBytes": return bytes((String)a[0]);
                case "bytesToString": return string((byte[])a[0]);
                case "buildHttpService": return service;
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
            if (!m.getName().equals("makeHttpRequest")) return null;
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
