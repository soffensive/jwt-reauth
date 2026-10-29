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

import com.google.gson.*;
import java.net.URL;
import java.util.*;
import java.util.regex.*;
import java.time.Instant;

/** Configuration is immutable; a renewal publishes a complete value snapshot. */
public final class SessionProfile {
    public enum Source { COOKIE, HEADER, JSON, REGEX }
    public enum Destination { VARIABLE, COOKIE, HEADER }
    public static final class Rule {
        public final String variable, selector, initial, target, prefix;
        public final Source source;
        public final Destination destination;
        public Rule(String variable, Source source, String selector, String initial,
                    Destination destination, String target) {
            this(variable, source, selector, initial, destination, target, "");
        }
        public Rule(String variable, Source source, String selector, String initial,
                    Destination destination, String target, String prefix) {
            if (prefix.contains("\r") || prefix.contains("\n")) throw new IllegalArgumentException("Prefix cannot contain newlines.");
            if (!variable.matches("[A-Za-z_][A-Za-z0-9_]*")) throw new IllegalArgumentException("Invalid variable name: " + variable);
            if (selector.isEmpty()) throw new IllegalArgumentException("An extractor needs a cookie name, header name, JSON path, or regex.");
            if (source == Source.REGEX && Pattern.compile(selector).matcher("").groupCount() < 1)
                throw new IllegalArgumentException("Regex needs a capture group.");
            if (destination != Destination.VARIABLE && !target.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+"))
                throw new IllegalArgumentException("Enter a valid destination cookie/header name.");
            if (destination == Destination.HEADER && (target.equalsIgnoreCase("Host") || target.equalsIgnoreCase("Content-Length") || target.equalsIgnoreCase("X-Reauth-Profile")))
                throw new IllegalArgumentException("Reserved destination header: " + target);
            this.variable = variable; this.source = source; this.selector = selector;
            this.initial = initial; this.destination = destination; this.target = target; this.prefix = prefix;
        }
        String extract(String response) {
            int split = response.indexOf("\r\n\r\n");
            String headers = split < 0 ? response : response.substring(0, split);
            if (source == Source.REGEX) {
                Matcher m = Pattern.compile(selector).matcher(response);
                return m.find() ? m.group(1) : null;
            }
            if (source == Source.JSON) {
                if (split < 0) return null;
                JsonElement value = JsonParser.parseString(response.substring(split + 4));
                for (String part : selector.split("\\.")) {
                    if (!value.isJsonObject() || !value.getAsJsonObject().has(part)) return null;
                    value = value.getAsJsonObject().get(part);
                }
                return value.isJsonPrimitive() ? value.getAsString() : null;
            }
            for (String line : headers.split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String name = line.substring(0, colon), value = line.substring(colon + 1).trim();
                if (source == Source.HEADER && name.equalsIgnoreCase(selector)) return value;
                if (source == Source.COOKIE && name.equalsIgnoreCase("Set-Cookie")) {
                    String cookie = value.split(";", 2)[0];
                    int eq = cookie.indexOf('=');
                    if (eq >= 0 && cookie.substring(0, eq).trim().equals(selector)) return cookie.substring(eq + 1);
                }
            }
            return null;
        }
    }
    public final String name, request;
    public final URL endpoint, scope;
    public final int interval;
    public final ReauthHttpClient.Protocol protocol;
    public final List<Rule> rules;
    public final boolean enabled, autoMatch;
    private volatile Map<String, String> values;
    public volatile String status = "Ready — not renewed yet";
    public volatile Instant lastSuccess, nextRenewal;
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)}");

    public SessionProfile(String name, URL endpoint, URL scope, String request, int interval,
                          List<Rule> rules, boolean enabled, boolean autoMatch) {
        this(name, endpoint, scope, request, interval, rules, enabled, autoMatch, ReauthHttpClient.Protocol.AUTO);
    }
    public SessionProfile(String name, URL endpoint, URL scope, String request, int interval,
                          List<Rule> rules, boolean enabled, boolean autoMatch, ReauthHttpClient.Protocol protocol) {
        this.protocol = Objects.requireNonNull(protocol);
        if (!name.matches("[A-Za-z0-9_-]+")) throw new IllegalArgumentException("Profile name must use letters, digits, underscores, or hyphens.");
        for (URL url : Arrays.asList(endpoint, scope)) {
            if (!(url.getProtocol().equals("http") || url.getProtocol().equals("https")) || url.getHost().isEmpty())
                throw new IllegalArgumentException("Use an HTTP or HTTPS URL.");
        }
        if (interval < 5) throw new IllegalArgumentException("Renewal interval must be at least 5 seconds.");
        this.request = request.replace("\r\n", "\n").replace("\n", "\r\n");
        ReauthHttpClient.validate(this.request);
        this.name = name; this.endpoint = endpoint; this.scope = scope; this.interval = interval;
        this.rules = Collections.unmodifiableList(new ArrayList<>(rules)); this.enabled = enabled; this.autoMatch = autoMatch;
        Map<String, String> initial = new LinkedHashMap<>();
        Set<String> destinations = new HashSet<>();
        for (Rule rule : rules) {
            if (initial.put(rule.variable, rule.initial) != null) throw new IllegalArgumentException("Duplicate variable: " + rule.variable);
            if (rule.destination != Destination.VARIABLE && !destinations.add(rule.destination + ":" + rule.target.toLowerCase(Locale.ROOT)))
                throw new IllegalArgumentException("Duplicate destination: " + rule.target);
        }
        values = Collections.unmodifiableMap(initial);
        Matcher m = PLACEHOLDER.matcher(this.request);
        while (m.find()) if (!initial.containsKey(m.group(1))) throw new IllegalArgumentException("Unknown variable: " + m.group(1));
    }
    public boolean matches(URL url) {
        String path = scope.getPath().isEmpty() ? "/" : scope.getPath();
        return sameOrigin(scope, url) && (url.getPath().equals(path) || url.getPath().startsWith(path.endsWith("/") ? path : path + "/"));
    }
    public static boolean sameOrigin(URL a, URL b) {
        return a.getProtocol().equalsIgnoreCase(b.getProtocol()) && a.getHost().equalsIgnoreCase(b.getHost())
                && port(a) == port(b);
    }
    public static int port(URL url) { return url.getPort() < 0 ? url.getDefaultPort() : url.getPort(); }
    public Map<String, String> snapshot() { return values; }
    void restoreValues(Map<String, String> saved) {
        if (!saved.keySet().equals(values.keySet()) || saved.values().stream().anyMatch(Objects::isNull))
            throw new IllegalArgumentException("Saved variables must match the extraction rules.");
        for (Rule rule : rules) {
            String value = saved.get(rule.variable);
            if (rule.destination != Destination.VARIABLE && (value.contains("\r") || value.contains("\n") ||
                    (rule.destination == Destination.COOKIE && value.contains(";"))))
                throw new IllegalArgumentException("Invalid saved value: " + rule.variable);
        }
        values = Collections.unmodifiableMap(new LinkedHashMap<>(saved));
        status = "Ready — loaded values; renewal required";
    }
    void inheritValues(SessionProfile previous) {
        Map<String, String> inherited = new LinkedHashMap<>(values);
        Map<String, String> oldValues = previous.snapshot();
        for (Rule rule : rules) for (Rule old : previous.rules) {
            if (rule.variable.equals(old.variable) && rule.source == old.source && rule.selector.equals(old.selector)
                    && rule.initial.equals(old.initial)) inherited.put(rule.variable, oldValues.get(old.variable));
        }
        values = Collections.unmodifiableMap(inherited);
    }
    public String render() {
        Map<String, String> snapshot = values;
        Matcher m = PLACEHOLDER.matcher(request);
        StringBuffer out = new StringBuffer();
        while (m.find()) m.appendReplacement(out, Matcher.quoteReplacement(snapshot.get(m.group(1))));
        m.appendTail(out); return out.toString();
    }
    public void accept(String response) {
        Map<String, String> updated = new LinkedHashMap<>(values);
        for (Rule rule : rules) {
            String value = rule.extract(response);
            if (value == null) throw new IllegalArgumentException("Missing response value: " + rule.variable);
            if (rule.destination != Destination.VARIABLE && (value.contains("\r") || value.contains("\n") ||
                    (rule.destination == Destination.COOKIE && value.contains(";"))))
                throw new IllegalArgumentException("Invalid value for destination: " + rule.variable);
            updated.put(rule.variable, value);
        }
        values = Collections.unmodifiableMap(updated);
    }
}
