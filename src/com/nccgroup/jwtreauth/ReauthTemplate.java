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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Stateful response variables for a raw HTTP re-authentication request. */
public final class ReauthTemplate {
    private static final Pattern VARIABLE = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)}");
    private final String request;
    private final Map<String, Pattern> extractors = new LinkedHashMap<>();
    private final Map<String, String> values = new LinkedHashMap<>();

    public ReauthTemplate(String request, String rules, String initialValues) {
        this.request = request.replace("\r\n", "\n").replace("\n", "\r\n");
        if (!this.request.contains("\r\n\r\n")) {
            throw new IllegalArgumentException("Request must contain a blank line between headers and body.");
        }
        parseLines(initialValues).forEach((name, value) -> values.put(name, value));
        parseLines(rules).forEach((name, regex) -> {
            Pattern pattern = Pattern.compile(regex);
            if (pattern.matcher("").groupCount() < 1) {
                throw new IllegalArgumentException("Extractor " + name + " needs a capture group.");
            }
            extractors.put(name, pattern);
        });
        Matcher placeholders = VARIABLE.matcher(this.request);
        while (placeholders.find()) {
            String name = placeholders.group(1);
            if (!values.containsKey(name)) {
                throw new IllegalArgumentException("Provide an initial value for " + name + ".");
            }
        }
    }

    private static Map<String, String> parseLines(String text) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String line : text.split("\\r?\\n")) {
            if (line.trim().isEmpty()) continue;
            int separator = line.indexOf('=');
            if (separator < 1) throw new IllegalArgumentException("Expected name=value on each line.");
            String name = line.substring(0, separator).trim();
            if (!name.matches("[A-Za-z_][A-Za-z0-9_]*")) {
                throw new IllegalArgumentException("Invalid variable name: " + name);
            }
            if (result.put(name, line.substring(separator + 1)) != null) {
                throw new IllegalArgumentException("Duplicate variable: " + name);
            }
        }
        return result;
    }

    public synchronized String render() {
        Matcher matcher = VARIABLE.matcher(request);
        StringBuffer result = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(result, Matcher.quoteReplacement(values.get(matcher.group(1))));
        }
        matcher.appendTail(result);
        return result.toString();
    }

    /** Missing matches preserve the previous value, including bootstrap values. */
    public synchronized void extract(String response) {
        extractors.forEach((name, pattern) -> {
            Matcher matcher = pattern.matcher(response);
            if (matcher.find() && matcher.group(1) != null) values.put(name, matcher.group(1));
        });
    }
}
