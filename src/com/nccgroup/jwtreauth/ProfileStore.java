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
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.net.URL;
import java.io.IOException;
import java.util.*;

/**
 * Versioned JSON persistence. Constructors validate every imported profile before use.
 * Version 2 stores scope as rule objects; version 1 files (a scope URL plus optional
 * "EXACT url" / "SUBTREE url" lines) are converted when loaded.
 */
public final class ProfileStore {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final class Document {
        Integer schemaVersion;
        List<ProfileData> profiles;
    }
    private static final int SCHEMA_VERSION = 2;
    private static final class ProfileData {
        String name, endpoint, request;
        // Version 1: a URL string; version 2: an array of ScopeData.
        JsonElement scope;
        String scopeRules; // Version 1 only.
        String loginRequest = "", loginEndpoint;
        int interval;
        boolean enabled, autoMatch, burpScope;
        ReauthHttpClient.Protocol protocol = ReauthHttpClient.Protocol.AUTO;
        List<RuleData> rules;
        Map<String, String> currentValues;
    }
    private static final class ScopeData {
        ScopeRule.Action action;
        ScopeRule.Match match;
        String url;
    }
    private static final class RuleData {
        String variable, selector, initial, target, prefix;
        SessionProfile.Source source;
        SessionProfile.Destination destination;
    }
    private ProfileStore() { }
    public static void save(Path destination, List<SessionProfile> profiles) throws IOException {
        Document document = new Document(); document.schemaVersion = SCHEMA_VERSION; document.profiles = new ArrayList<>();
        for (SessionProfile profile : profiles) {
            ProfileData data = new ProfileData();
            data.name = profile.name; data.endpoint = profile.endpoint.toString(); data.burpScope = profile.burpScope;
            List<ScopeData> scope = new ArrayList<>();
            for (ScopeRule rule : profile.scope) {
                ScopeData d = new ScopeData(); d.action = rule.action; d.match = rule.match; d.url = rule.url.toString(); scope.add(d);
            }
            data.scope = GSON.toJsonTree(scope);
            data.loginRequest = profile.loginRequest; data.loginEndpoint = profile.loginEndpoint == null ? null : profile.loginEndpoint.toString();
            data.request = profile.request; data.interval = profile.interval; data.enabled = profile.enabled;
            data.autoMatch = profile.autoMatch; data.protocol = profile.protocol; data.currentValues = profile.snapshot();
            data.rules = new ArrayList<>();
            for (SessionProfile.Rule rule : profile.rules) {
                RuleData r = new RuleData(); r.variable = rule.variable; r.source = rule.source; r.selector = rule.selector;
                r.initial = rule.initial; r.destination = rule.destination; r.target = rule.target; r.prefix = rule.prefix;
                data.rules.add(r);
            }
            document.profiles.add(data);
        }
        Path target = destination.toAbsolutePath();
        Path temporary = Files.createTempFile(target.getParent(), ".jwt-reauth-", ".tmp");
        try {
            Files.writeString(temporary, GSON.toJson(document) + "\n", StandardCharsets.UTF_8);
            try { Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
            catch (AtomicMoveNotSupportedException ex) { Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING); }
        } finally { Files.deleteIfExists(temporary); }
    }
    public static List<SessionProfile> load(Path source) throws IOException {
        if (Files.size(source) > 32L * 1024 * 1024) throw new IOException("Profile file exceeds 32 MiB.");
        try {
            Document document = GSON.fromJson(Files.readString(source, StandardCharsets.UTF_8), Document.class);
            if (document == null || document.schemaVersion == null || document.schemaVersion < 1 || document.schemaVersion > SCHEMA_VERSION || document.profiles == null)
                throw new IllegalArgumentException("Expected a profile file with schemaVersion 1 or 2 and a profiles array.");
            Set<String> names = new HashSet<>(); List<SessionProfile> result = new ArrayList<>();
            for (ProfileData data : document.profiles) {
                Objects.requireNonNull(data); Objects.requireNonNull(data.rules);
                if (!names.add(data.name)) throw new IllegalArgumentException("Duplicate profile: " + data.name);
                List<SessionProfile.Rule> rules = new ArrayList<>();
                for (RuleData r : data.rules) {
                    Objects.requireNonNull(r); Objects.requireNonNull(r.source); Objects.requireNonNull(r.destination);
                    rules.add(new SessionProfile.Rule(Objects.requireNonNull(r.variable), r.source, Objects.requireNonNull(r.selector),
                            Objects.requireNonNull(r.initial), r.destination, Objects.requireNonNull(r.target), Objects.requireNonNull(r.prefix)));
                }
                List<ScopeRule> scope = document.schemaVersion == 1 ? migrateScope(data) : readScope(data);
                SessionProfile profile = new SessionProfile(Objects.requireNonNull(data.name), new URL(data.endpoint), scope, data.burpScope,
                        Objects.requireNonNull(data.request), data.interval, rules, data.enabled, data.autoMatch, Objects.requireNonNull(data.protocol));
                profile.configureWorkflow(data.loginRequest, data.loginEndpoint == null ? null : new URL(data.loginEndpoint));
                if (data.currentValues != null) profile.restoreValues(data.currentValues);
                result.add(profile);
            }
            return result;
        } catch (RuntimeException ex) { throw new IOException("Invalid profile file: " + (ex.getMessage() == null ? "missing or invalid field" : ex.getMessage()), ex); }
    }
    private static List<ScopeRule> readScope(ProfileData data) throws java.net.MalformedURLException {
        if (data.scope == null || !data.scope.isJsonArray()) throw new IllegalArgumentException("Expected a scope array.");
        List<ScopeRule> scope = new ArrayList<>();
        for (JsonElement element : data.scope.getAsJsonArray()) {
            ScopeData d = Objects.requireNonNull(GSON.fromJson(element, ScopeData.class));
            scope.add(new ScopeRule(Objects.requireNonNull(d.action), Objects.requireNonNull(d.match), new URL(Objects.requireNonNull(d.url))));
        }
        return scope;
    }
    /** Version 1: SUBTREE lines become prefix includes and EXACT lines exact includes; without lines, the scope URL is a prefix include. */
    private static List<ScopeRule> migrateScope(ProfileData data) throws java.net.MalformedURLException {
        if (data.scope == null || !data.scope.isJsonPrimitive()) throw new IllegalArgumentException("Expected a scope URL.");
        List<ScopeRule> scope = new ArrayList<>();
        for (String line : (data.scopeRules == null ? "" : data.scopeRules).split("\r?\n")) if (!line.isBlank()) {
            if (!(line.startsWith("EXACT ") || line.startsWith("SUBTREE "))) throw new IllegalArgumentException("Invalid version 1 scope rule: " + line);
            scope.add(new ScopeRule(ScopeRule.Action.INCLUDE, line.startsWith("EXACT ") ? ScopeRule.Match.EXACT : ScopeRule.Match.PREFIX,
                    new URL(line.substring(line.indexOf(' ') + 1).trim())));
        }
        if (scope.isEmpty()) scope.add(ScopeRule.include(new URL(data.scope.getAsString())));
        return scope;
    }
}
