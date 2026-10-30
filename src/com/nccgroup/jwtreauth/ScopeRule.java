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

import java.net.URL;
import java.util.Objects;

/** One row of a profile's scope: origin plus a path prefix or exact path. Exclusions win over inclusions. */
public final class ScopeRule {
    public enum Action { INCLUDE, EXCLUDE }
    /** PREFIX matches the path and everything below it on a segment boundary; EXACT matches the path only. */
    public enum Match { PREFIX, EXACT }
    public final Action action;
    public final Match match;
    public final URL url;

    public ScopeRule(Action action, Match match, URL url) {
        this.action = Objects.requireNonNull(action); this.match = Objects.requireNonNull(match); this.url = Objects.requireNonNull(url);
        if (!url.getProtocol().matches("https?") || url.getHost().isEmpty())
            throw new IllegalArgumentException("Scope rules need an HTTP(S) URL with a host: " + url);
    }
    public static ScopeRule include(URL url) { return new ScopeRule(Action.INCLUDE, Match.PREFIX, url); }

    /** Query strings are ignored; dot-segment paths never match, since servers resolve them past the prefix. */
    public boolean matches(URL target) {
        if (!SessionProfile.sameOrigin(url, target) || hasDotSegment(target.getPath())) return false;
        String path = normalize(url.getPath()), candidate = normalize(target.getPath());
        if (match == Match.EXACT) return candidate.equals(path);
        return candidate.equals(path) || candidate.startsWith(path.endsWith("/") ? path : path + "/");
    }
    private static String normalize(String path) { return path.isEmpty() ? "/" : path; }
    static boolean hasDotSegment(String path) {
        for (String segment : path.split("/", -1)) {
            String decoded = segment.replaceAll("(?i)%2e", ".");
            if (decoded.equals(".") || decoded.equals("..")) return true;
        }
        return false;
    }
    @Override public boolean equals(Object other) {
        if (!(other instanceof ScopeRule)) return false;
        ScopeRule rule = (ScopeRule) other;
        return action == rule.action && match == rule.match && url.toString().equals(rule.url.toString());
    }
    @Override public int hashCode() { return Objects.hash(action, match, url.toString()); }
    @Override public String toString() { return action + " " + match + " " + url; }
}
