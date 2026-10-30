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
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Routes traffic and schedules isolated, non-overlapping profile renewals. */
public final class SessionProfiles implements IExtensionStateListener {
    public static final String MARKER = "X-Reauth-Profile";
    private final JWTReauth extension;
    private final IExtensionHelpers helpers;
    private final ScheduledExecutorService workers = Executors.newScheduledThreadPool(4);
    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private final ThreadLocal<Boolean> renewing = ThreadLocal.withInitial(() -> false);
    private volatile boolean closed;
    private final RequestDebugLog debugLog = new RequestDebugLog();
    public RequestDebugLog getDebugLog() { return debugLog; }
    private final ConcurrentHashMap<String, Integer> inFlight = new ConcurrentHashMap<>();
    private volatile boolean logUnmatched;
    /** Unmatched traffic is not recorded by default so browsing cannot push renewals out of the history. */
    public void setLogUnmatched(boolean enabled) { logUnmatched = enabled; }
    private static final class Entry {
        final SessionProfile profile;
        final AtomicBoolean busy = new AtomicBoolean();
        /** Set after a failed refresh so the next attempt logs in again, if a login request exists. */
        volatile boolean loginNext;
        ScheduledFuture<?> schedule;
        Entry(SessionProfile profile) { this.profile = profile; }
    }
    public SessionProfiles(JWTReauth extension) {
        this.extension = extension; helpers = extension.getCallbacks().getHelpers();
    }
    public synchronized List<SessionProfile> list() {
        List<SessionProfile> profiles = new ArrayList<>();
        entries.values().forEach(e -> profiles.add(e.profile)); return profiles;
    }
    public synchronized void save(SessionProfile profile, String replacing) {
        if (closed) throw new IllegalStateException("Extension unloaded");
        if (!profile.name.equals(replacing) && entries.containsKey(profile.name))
            throw new IllegalArgumentException("A profile with this name already exists.");
        Entry previous = replacing == null ? null : entries.get(replacing);
        if (previous != null) profile.inheritValues(previous.profile);
        if (replacing != null) remove(replacing);
        Entry entry = new Entry(profile); entries.put(profile.name, entry);
        if (profile.enabled) {
            profile.nextRenewal = Instant.now();
            entry.schedule = workers.scheduleWithFixedDelay(() -> renew(entry), 0, profile.interval, TimeUnit.SECONDS);
        }
    }
    /** Toggle scheduling and injection without replacing tokens or an in-flight renewal. */
    public synchronized void setEnabled(String name, boolean enabled) {
        if (closed) throw new IllegalStateException("Extension unloaded");
        Entry entry = entries.get(name);
        if (entry == null || entry.profile.enabled == enabled) return;
        entry.profile.enabled = enabled;
        if (entry.schedule != null) { entry.schedule.cancel(false); entry.schedule = null; }
        entry.profile.nextRenewal = enabled ? Instant.now() : null;
        if (enabled) entry.schedule = workers.scheduleWithFixedDelay(() -> renew(entry), 0, entry.profile.interval, TimeUnit.SECONDS);
    }
    /** Merge a fully validated file; imported values replace same-name profile state. */
    public synchronized void loadProfiles(List<SessionProfile> profiles) {
        if (closed) throw new IllegalStateException("Extension unloaded");
        Set<String> names = new HashSet<>();
        for (SessionProfile profile : profiles) {
            Objects.requireNonNull(profile);
            if (!names.add(profile.name)) throw new IllegalArgumentException("Duplicate profile: " + profile.name);
        }
        for (SessionProfile profile : profiles) {
            remove(profile.name);
            save(profile, null);
        }
    }
    public synchronized void remove(String name) {
        Entry entry = entries.remove(name);
        if (entry != null && entry.schedule != null) entry.schedule.cancel(false);
    }
    public synchronized void test(String name) {
        Entry entry = entries.get(name);
        if (entry != null && !closed && entry.busy.compareAndSet(false, true))
            workers.execute(() -> runRenewal(entry));
    }
    private synchronized boolean active(Entry entry) { return !closed && entries.get(entry.profile.name) == entry; }
    private void renew(Entry entry) {
        if (!active(entry) || !entry.profile.enabled || !entry.busy.compareAndSet(false, true)) return;
        runRenewal(entry);
    }
    private void runRenewal(Entry entry) {
        if (!active(entry)) { entry.busy.set(false); return; }
        SessionProfile profile = entry.profile;
        profile.status = "Renewing";
        String flightKey = null, targetKey = null;
        String requestText = "", responseText = "", exchangeUrl = profile.endpoint.toString();
        Map<String, String> previousValues = profile.snapshot();
        boolean login = !profile.loginRequest.isBlank() && (profile.lastSuccess == null || entry.loginNext);
        try {
            renewing.set(true);
            URL destination = login ? profile.loginEndpoint : profile.endpoint;
            exchangeUrl = destination.toString();
            byte[] raw = helpers.stringToBytes(login ? profile.render(profile.loginRequest) : profile.render());
            IHttpService service = helpers.buildHttpService(destination.getHost(), SessionProfile.port(destination), destination.getProtocol());
            ReauthHttpClient client = new ReauthHttpClient(extension.getCallbacks());
            ReauthHttpClient.Prepared prepared = client.prepare(service, raw, profile.protocol);
            requestText = helpers.bytesToString(prepared.request);
            flightKey = fingerprint(service, prepared.request);
            inFlight.merge(flightKey, 1, Integer::sum);
            targetKey = targetFingerprint(service, prepared.request);
            inFlight.merge(targetKey, 1, Integer::sum);
            byte[] response = client.send(service, prepared);
            if (response == null) throw new IllegalArgumentException("No HTTP response");
            responseText = helpers.bytesToString(response);
            int status = helpers.analyzeResponse(response).getStatusCode();
            if (status < 200 || status >= 300) throw new IllegalArgumentException("HTTP " + status);
            // Publish under the registry lock: an edit either inherits these values or discards them, never a stale mix.
            synchronized (this) {
                if (!active(entry)) {
                    debugLog.addRenewal(profile.name, exchangeUrl, "Discarded result: profile deleted or replaced", requestText, responseText, "Profile no longer active.");
                    return;
                }
                profile.accept(responseText);
            }
            List<String> results = new ArrayList<>();
            profile.snapshot().forEach((name, value) -> results.add(name + (Objects.equals(previousValues.get(name), value) ? " unchanged" : " updated")));
            entry.loginNext = false;
            profile.lastSuccess = Instant.now();
            profile.status = "Ready — " + String.join(", ", results);
            debugLog.addRenewal(profile.name, exchangeUrl, profile.status, requestText, responseText,
                    "Workflow step: " + (login ? "Login" : "Refresh") + "\nProtocol: " + prepared.description() + "\nPrevious variables: " + previousValues + "\nCurrent variables: " + profile.snapshot());
        } catch (RuntimeException ex) {
            // The status appears in the overview, so keep parser and HTTP helper messages (which may contain
            // secrets) out of it. The debug log already shows requests and tokens in full, so it gets the exception.
            boolean retryLogin = !login && !profile.loginRequest.isBlank();
            if (retryLogin) entry.loginNext = true;
            profile.status = "Failed — " + (ex instanceof com.google.gson.JsonParseException ? "malformed JSON; previous values retained" : ex instanceof IllegalArgumentException && ex.getMessage() != null &&
                    (ex.getMessage().startsWith("Missing response value:") || ex.getMessage().startsWith("Invalid value for destination:") || ex.getMessage().startsWith("HTTP ") || ex.getMessage().equals("No HTTP response"))
                    ? ex.getMessage() : "invalid response or request; previous values retained") + (retryLogin ? "; next attempt logs in" : "");
            debugLog.addRenewal(profile.name, exchangeUrl, profile.status, requestText, responseText,
                    "Workflow step: " + (login ? "Login" : "Refresh") + "\nRetained variables: " + profile.snapshot() + "\n" + ex + "\nProtocol: " + profile.protocol);
        } finally {
            if (flightKey != null) inFlight.computeIfPresent(flightKey, (key, count) -> count == 1 ? null : count - 1);
            if (targetKey != null) inFlight.computeIfPresent(targetKey, (key, count) -> count == 1 ? null : count - 1);
            renewing.remove();
            profile.nextRenewal = profile.enabled ? Instant.now().plusSeconds(profile.interval) : null;
            entry.busy.set(false);
        }
    }
    /** Returns true when a profile owns this request, including conflicts and unknown markers. */
    public boolean process(boolean isRequest, IHttpRequestResponse message) {
        if (!isRequest) return false;
        // A native HTTP/2 renewal must not pass through the legacy byte-array
        // view. Burp may normalize a kettled request when getRequest() is called,
        // including removing pseudo-headers. Its actual request is already
        // recorded by runRenewal(), so bypass before reading or analyzing it.
        if (renewing.get()) return true;
        byte[] original = message.getRequest().clone();
        IRequestInfo info = helpers.analyzeRequest(message);
        List<String> headers = new ArrayList<>(info.getHeaders());
        List<String> markers = new ArrayList<>();
        headers.removeIf(h -> {
            int colon = h.indexOf(':');
            if (colon > 0 && h.substring(0, colon).equalsIgnoreCase(MARKER)) {
                markers.add(h.substring(colon + 1).trim()); return true;
            }
            return false;
        });
        byte[] body = Arrays.copyOfRange(message.getRequest(), info.getBodyOffset(), message.getRequest().length);
        if (!markers.isEmpty()) message.setRequest(helpers.buildHttpMessage(headers, body));
        URL url = info.getUrl();
        List<SessionProfile> profiles = list();
        if (renewing.get() || inFlight.containsKey(fingerprint(message.getHttpService(), message.getRequest()))
                || inFlight.containsKey(targetFingerprint(message.getHttpService(), message.getRequest()))
                || profiles.stream().anyMatch(p -> isEndpoint(p.endpoint, url) || isEndpoint(p.loginEndpoint, url))) {
            recordRequest("", url, "Renewal/authentication request: credential injection bypassed", original, message);
            return true;
        }
        List<SessionProfile> matches = new ArrayList<>();
        for (SessionProfile p : profiles) {
            boolean selected = p.autoMatch ? markers.isEmpty() : markers.size() == 1 && p.name.equals(markers.get(0));
            if (p.enabled && selected && p.matches(url, extension.getCallbacks()::isInScope)) matches.add(p);
        }
        if (matches.size() != 1) {
            if (!markers.isEmpty() || matches.size() > 1) {
                String reason;
                if (markers.size() > 1) reason = "Multiple profile markers; credentials not injected";
                else if (!markers.isEmpty()) {
                    SessionProfile named = profiles.stream().filter(p -> p.name.equals(markers.get(0))).findFirst().orElse(null);
                    reason = named == null ? "Unknown profile; credentials not injected"
                            : !named.enabled ? "Profile disabled; credentials not injected"
                            : named.autoMatch ? "Profile uses Scope mode, not Marker mode; credentials not injected"
                            : "Outside profile scope for marker; credentials not injected";
                } else reason = "Ambiguous profiles: " + matches.stream().map(p -> p.name).collect(java.util.stream.Collectors.joining(", ")) + "; credentials not injected";
                extension.getLogController().info("%s", reason);
                recordRequest(String.join(", ", markers), url, reason, original, message);
                return true;
            }
            if (logUnmatched) debugLog.add("Routing", "", url.toString(), "No enabled session profile matched; request unchanged",
                    helpers.bytesToString(original), helpers.bytesToString(message.getRequest()), "No enabled profile selected by marker or automatic scope matching.");
            return false;
        }
        SessionProfile profile = matches.get(0);
        if (profile.lastSuccess == null) {
            extension.getLogController().info("Session profile has no successful renewal yet; credentials were not injected.");
            recordRequest(profile.name, url, "No successful renewal yet; credentials not injected", original, message);
            return true;
        }
        Map<String, String> values = profile.snapshot();
        Map<String, String> cookies = new LinkedHashMap<>();
        for (String header : headers) if (header.regionMatches(true, 0, "Cookie:", 0, 7)) {
            for (String item : header.substring(7).split(";")) {
                int eq = item.indexOf('=');
                if (eq > 0) cookies.put(item.substring(0, eq).trim(), item.substring(eq + 1).trim());
            }
        }
        boolean changedCookies = false;
        for (SessionProfile.Rule rule : profile.rules) {
            String value = rule.prefix + values.get(rule.variable);
            if (rule.destination == SessionProfile.Destination.HEADER) {
                headers.removeIf(h -> h.regionMatches(true, 0, rule.target + ":", 0, rule.target.length() + 1));
                headers.add(rule.target + ": " + value);
            } else if (rule.destination == SessionProfile.Destination.COOKIE) {
                cookies.put(rule.target, value); changedCookies = true;
            }
        }
        if (changedCookies) {
            headers.removeIf(h -> h.regionMatches(true, 0, "Cookie:", 0, 7));
            List<String> pairs = new ArrayList<>(); cookies.forEach((k, v) -> pairs.add(k + "=" + v));
            headers.add("Cookie: " + String.join("; ", pairs));
        }
        message.setRequest(helpers.buildHttpMessage(headers, body));
        recordRequest(profile.name, url, "Applied profile via " + (markers.isEmpty() ? "scope" : "marker"), original, message);
        return true;
    }
    public void recordRequest(String profile, URL url, String reason, byte[] before, IHttpRequestResponse message) {
        String original = helpers.bytesToString(before), updated = helpers.bytesToString(message.getRequest());
        StringBuilder changes = new StringBuilder();
        List<String> oldHeaders = new ArrayList<>(Arrays.asList(original.split("\r\n\r\n", 2)[0].split("\r\n")));
        List<String> newHeaders = new ArrayList<>(Arrays.asList(updated.split("\r\n\r\n", 2)[0].split("\r\n")));
        for (String header : new ArrayList<>(oldHeaders)) if (newHeaders.remove(header)) oldHeaders.remove(header);
        for (String header : oldHeaders) changes.append("Removed: ").append(header).append("\n");
        for (String header : newHeaders) changes.append("Added: ").append(header).append("\n");
        if (original.equals(updated)) changes.append("Request unchanged.\n");
        debugLog.add("Request", profile, url.toString(), reason, original, updated, changes.toString());
    }
    private static boolean isEndpoint(URL endpoint, URL url) {
        return endpoint != null && SessionProfile.sameOrigin(endpoint, url) && endpoint.getPath().equals(url.getPath());
    }
    private String targetFingerprint(IHttpService service, byte[] request) {
        String[] line = helpers.bytesToString(request).split("\r\n", 2)[0].split(" ", 3);
        String target = line.length > 1 ? line[1] : "";
        if (target.startsWith("http://") || target.startsWith("https://")) {
            java.net.URI uri = java.net.URI.create(target);
            target = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            if (uri.getRawQuery() != null) target += "?" + uri.getRawQuery();
        }
        return "target:" + service.getProtocol() + "://" + service.getHost().toLowerCase(Locale.ROOT) + ":" + service.getPort() + ":" + line[0] + ":" + target;
    }
    private static String fingerprint(IHttpService service, byte[] request) {
        try {
            return service.getProtocol() + "://" + service.getHost().toLowerCase(Locale.ROOT) + ":" + service.getPort()
                    + ":" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(request));
        } catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
    @Override public synchronized void extensionUnloaded() {
        closed = true; entries.values().forEach(e -> { if (e.schedule != null) e.schedule.cancel(true); });
        entries.clear(); workers.shutdownNow();
    }
}
