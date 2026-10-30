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

/** Versioned JSON persistence. Constructors validate every imported profile before use. */
public final class ProfileStore {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final class Document {
        Integer schemaVersion;
        List<ProfileData> profiles;
    }
    private static final class ProfileData {
        String name, endpoint, scope, request;
        String loginRequest = "", loginEndpoint, scopeRules = "";
        int interval;
        boolean enabled, autoMatch;
        ReauthHttpClient.Protocol protocol = ReauthHttpClient.Protocol.AUTO;
        List<RuleData> rules;
        Map<String, String> currentValues;
    }
    private static final class RuleData {
        String variable, selector, initial, target, prefix;
        SessionProfile.Source source;
        SessionProfile.Destination destination;
    }
    private ProfileStore() { }
    public static void save(Path destination, List<SessionProfile> profiles) throws IOException {
        Document document = new Document(); document.schemaVersion = 1; document.profiles = new ArrayList<>();
        for (SessionProfile profile : profiles) {
            ProfileData data = new ProfileData();
            data.name = profile.name; data.endpoint = profile.endpoint.toString(); data.scope = profile.scope.toString();
            data.loginRequest = profile.loginRequest; data.loginEndpoint = profile.loginEndpoint == null ? null : profile.loginEndpoint.toString(); data.scopeRules = profile.scopeRules;
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
            if (document == null || !Integer.valueOf(1).equals(document.schemaVersion) || document.profiles == null)
                throw new IllegalArgumentException("Expected a profile file with schemaVersion 1 and a profiles array.");
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
                SessionProfile profile = new SessionProfile(Objects.requireNonNull(data.name), new URL(data.endpoint), new URL(data.scope),
                        Objects.requireNonNull(data.request), data.interval, rules, data.enabled, data.autoMatch, Objects.requireNonNull(data.protocol));
                profile.configureWorkflow(data.loginRequest, data.loginEndpoint == null ? null : new URL(data.loginEndpoint), data.scopeRules);
                if (data.currentValues != null) profile.restoreValues(data.currentValues);
                result.add(profile);
            }
            return result;
        } catch (RuntimeException ex) { throw new IOException("Invalid profile file: " + (ex.getMessage() == null ? "missing or invalid field" : ex.getMessage()), ex); }
    }
}
