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
    private final ConcurrentHashMap<String, Integer> inFlight = new ConcurrentHashMap<>();
    private static final class Entry {
        final SessionProfile profile;
        final AtomicBoolean busy = new AtomicBoolean();
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
        if (!active(entry) || !entry.busy.compareAndSet(false, true)) return;
        runRenewal(entry);
    }
    private void runRenewal(Entry entry) {
        if (!active(entry)) { entry.busy.set(false); return; }
        SessionProfile profile = entry.profile;
        profile.status = "Renewing";
        String flightKey = null;
        try {
            renewing.set(true);
            byte[] raw = helpers.stringToBytes(profile.render());
            IRequestInfo info = helpers.analyzeRequest(raw);
            List<String> headers = new ArrayList<>(info.getHeaders());
            headers.removeIf(h -> h.regionMatches(true, 0, MARKER + ":", 0, MARKER.length() + 1));
            byte[] request = helpers.buildHttpMessage(headers, Arrays.copyOfRange(raw, info.getBodyOffset(), raw.length));
            IHttpService service = helpers.buildHttpService(profile.endpoint.getHost(), SessionProfile.port(profile.endpoint), profile.endpoint.getProtocol());
            flightKey = fingerprint(service, request);
            inFlight.merge(flightKey, 1, Integer::sum);
            IHttpRequestResponse response = extension.getCallbacks().makeHttpRequest(service, request);
            if (response == null || response.getResponse() == null) throw new IllegalArgumentException("No HTTP response");
            int status = helpers.analyzeResponse(response.getResponse()).getStatusCode();
            if (status < 200 || status >= 300) throw new IllegalArgumentException("HTTP " + status);
            if (!active(entry)) return;
            Map<String, String> before = profile.snapshot();
            profile.accept(helpers.bytesToString(response.getResponse()));
            List<String> results = new ArrayList<>();
            profile.snapshot().forEach((name, value) -> results.add(name + (Objects.equals(before.get(name), value) ? " unchanged" : " updated")));
            profile.lastSuccess = Instant.now();
            profile.status = "Ready — " + String.join(", ", results) + " (values masked)";
        } catch (RuntimeException ex) {
            // Do not include exception messages from parsers or HTTP helpers: they may contain secrets.
            profile.status = "Failed — " + (ex instanceof com.google.gson.JsonParseException ? "malformed JSON; previous values retained" : ex instanceof IllegalArgumentException && ex.getMessage() != null &&
                    (ex.getMessage().startsWith("Missing response value:") || ex.getMessage().startsWith("Invalid value for destination:") || ex.getMessage().startsWith("HTTP ") || ex.getMessage().equals("No HTTP response"))
                    ? ex.getMessage() : "invalid response or request; previous values retained");
        } finally {
            if (flightKey != null) inFlight.computeIfPresent(flightKey, (key, count) -> count == 1 ? null : count - 1);
            renewing.remove();
            profile.nextRenewal = profile.enabled ? Instant.now().plusSeconds(profile.interval) : null;
            entry.busy.set(false);
        }
    }
    /** Returns true when a profile owns this request, including conflicts and unknown markers. */
    public boolean process(boolean isRequest, IHttpRequestResponse message) {
        if (!isRequest) return false;
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
        if (renewing.get() || inFlight.containsKey(fingerprint(message.getHttpService(), message.getRequest())) || profiles.stream().anyMatch(p -> SessionProfile.sameOrigin(p.endpoint, url)
                && p.endpoint.getPath().equals(url.getPath()))) return true;
        List<SessionProfile> matches = new ArrayList<>();
        for (SessionProfile p : profiles) {
            if (p.enabled && p.matches(url) && (markers.isEmpty() ? p.autoMatch : markers.size() == 1 && p.name.equals(markers.get(0)))) matches.add(p);
        }
        if (matches.size() != 1) {
            if (!markers.isEmpty() || matches.size() > 1) {
                extension.getLogController().info("Session profile selection failed: unknown, disabled, outside scope, or ambiguous profile. Credentials were not injected.");
                return true;
            }
            return false;
        }
        SessionProfile profile = matches.get(0);
        if (profile.lastSuccess == null) {
            extension.getLogController().info("Session profile has no successful renewal yet; credentials were not injected.");
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
        message.setRequest(helpers.buildHttpMessage(headers, body)); return true;
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
