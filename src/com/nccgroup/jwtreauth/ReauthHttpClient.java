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
import java.util.*;
import java.net.URI;
import java.io.ByteArrayOutputStream;

/** Adapts Burp's editable HTTP representation to its HTTP/1 and HTTP/2 APIs. */
public final class ReauthHttpClient {
    public enum Protocol {
        AUTO("Automatic (Burp settings / request version)"), HTTP_1("HTTP/1"), HTTP_2("HTTP/2");
        private final String label;
        Protocol(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }
    public static final class Prepared {
        public final byte[] request, body;
        public final List<IHttpHeader> headers;
        public final boolean http2, forceHttp1;
        private Prepared(byte[] request, byte[] body, List<IHttpHeader> headers, boolean http2, boolean forceHttp1) {
            this.request = request; this.body = body; this.headers = headers; this.http2 = http2; this.forceHttp1 = forceHttp1;
        }
        public String description() { return http2 ? "HTTP/2" : forceHttp1 ? "HTTP/1" : "Automatic (Burp settings)"; }
    }
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    public ReauthHttpClient(IBurpExtenderCallbacks callbacks) { this.callbacks = callbacks; helpers = callbacks.getHelpers(); }
    public static void validate(String request) {
        int end = request.indexOf("\r\n");
        String[] line = (end < 0 ? request : request.substring(0, end)).split(" ", 3);
        if (line.length != 3 || !line[0].matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+") || line[1].isEmpty() || !request.contains("\r\n\r\n"))
            throw new IllegalArgumentException("Enter a complete HTTP request with a method, target, version, and blank line after headers.");
        if (!Arrays.asList("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0").contains(line[2]))
            throw new IllegalArgumentException("This Burp API supports HTTP/1.0, HTTP/1.1, and HTTP/2 request representations.");
    }
    public Prepared prepare(IHttpService service, byte[] raw, Protocol protocol) {
        String text = helpers.bytesToString(raw); validate(text);
        int split = text.indexOf("\r\n\r\n");
        List<String> headers = new ArrayList<>(Arrays.asList(text.substring(0, split).split("\r\n")));
        String[] line = headers.get(0).split(" ", 3);
        byte[] body = Arrays.copyOfRange(raw, split + 4, raw.length);
        headers.removeIf(h -> h.regionMatches(true, 0, SessionProfiles.MARKER + ":", 0, SessionProfiles.MARKER.length() + 1));
        boolean http2 = protocol == Protocol.HTTP_2 || (protocol == Protocol.AUTO && line[2].startsWith("HTTP/2"));
        if (!http2) {
            String version = line[2].equals("HTTP/1.0") ? "HTTP/1.0" : "HTTP/1.1";
            headers.set(0, line[0] + " " + line[1] + " " + version);
            return new Prepared(helpers.buildHttpMessage(headers, body), body, Collections.emptyList(), false,
                    protocol == Protocol.HTTP_1 || line[2].equals("HTTP/1.0"));
        }
        Map<String, List<String>> fields = new LinkedHashMap<>();
        for (int i = 1; i < headers.size(); i++) {
            int colon = headers.get(i).indexOf(':');
            if (colon <= 0) throw new IllegalArgumentException("Invalid HTTP header in renewal request.");
            String name = headers.get(i).substring(0, colon).trim().toLowerCase(Locale.ROOT);
            if (!name.matches("[!#$%&'*+.^_`|~0-9a-z-]+"))
                throw new IllegalArgumentException("Invalid HTTP/2 header name in renewal request: " + name);
            String value = headers.get(i).substring(colon + 1).replaceAll("^[ \t]+|[ \t]+$", "");
            validateFieldValue(value, name);
            fields.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
        if (fields.containsKey("transfer-encoding")) {
            if (!String.join(",", fields.get("transfer-encoding")).equalsIgnoreCase("chunked"))
                throw new IllegalArgumentException("Unsupported transfer encoding for HTTP/2 conversion.");
            body = dechunk(body);
        }
        String authority = fields.containsKey("host") ? fields.get("host").get(0) : service.getHost();
        if (!fields.containsKey("host")) {
            if (authority.contains(":") && !authority.startsWith("[")) authority = "[" + authority + "]";
            if (service.getPort() != (service.getProtocol().equals("https") ? 443 : 80)) authority += ":" + service.getPort();
        }
        String target = line[1];
        if (target.startsWith("http://") || target.startsWith("https://")) {
            URI uri = URI.create(target);
            if (!fields.containsKey("host")) authority = uri.getRawAuthority();
            target = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            if (uri.getRawQuery() != null) target += "?" + uri.getRawQuery();
        }
        if (authority.isEmpty() || authority.chars().anyMatch(c -> c <= 32 || c == 127))
            throw new IllegalArgumentException("Invalid Host/authority for HTTP/2 renewal.");
        if (target.chars().anyMatch(c -> c <= 32 || c == 127))
            throw new IllegalArgumentException("Invalid target for HTTP/2 renewal.");
        List<IHttpHeader> converted = new ArrayList<>();
        // Burp's HTTP/1-style editor requires this exact pseudo-header order.
        // Although the reverse scheme/method order is valid HTTP/2, Burp flags
        // both fields as reordered and marks that request as kettled.
        if (line[0].equals("CONNECT")) {
            converted.add(helpers.buildHeader(":method", line[0]));
            authority = target;
        } else {
            converted.add(helpers.buildHeader(":scheme", service.getProtocol()));
            converted.add(helpers.buildHeader(":method", line[0]));
            converted.add(helpers.buildHeader(":path", target));
        }
        converted.add(helpers.buildHeader(":authority", authority));
        Set<String> omit = new HashSet<>(Arrays.asList("host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "http2-settings", "content-length"));
        for (String value : fields.getOrDefault("connection", Collections.emptyList()))
            for (String name : value.split(",")) omit.add(name.trim().toLowerCase(Locale.ROOT));
        fields.forEach((name, values) -> {
            if (omit.contains(name)) return;
            for (String value : values) {
                if (name.equals("cookie")) {
                    // Burp treats a semicolon-space inside one HTTP/2 cookie field
                    // as kettled. RFC 9113 section 8.2.3 permits one field per crumb.
                    // Preserve order and duplicate names, including '=' inside values.
                    for (String crumb : value.split(";", -1)) {
                        String cookie = crumb.trim();
                        if (!cookie.isEmpty()) converted.add(helpers.buildHeader("cookie", cookie));
                    }
                } else if (!name.equals("te") || value.equalsIgnoreCase("trailers")) {
                    converted.add(helpers.buildHeader(name, value));
                }
            }
        });
        if (body.length > 0 || fields.containsKey("content-length")) converted.add(helpers.buildHeader("content-length", Integer.toString(body.length)));
        // Keep an HTTP-style representation for debugging and listener isolation.
        List<String> display = new ArrayList<>(); display.add(line[0] + " " + target + " HTTP/2"); display.add("Host: " + authority);
        for (IHttpHeader field : converted) if (!field.getName().startsWith(":")) display.add(field.getName() + ": " + field.getValue());
        return new Prepared(helpers.buildHttpMessage(display, body), body, Collections.unmodifiableList(converted), true, false);
    }
    public byte[] send(IHttpService service, Prepared prepared) {
        if (prepared.http2) return callbacks.makeHttp2Request(service, prepared.headers, prepared.body, true);
        IHttpRequestResponse response = callbacks.makeHttpRequest(service, prepared.request, prepared.forceHttp1);
        return response == null ? null : response.getResponse();
    }
    private static void validateFieldValue(String value, String name) {
        if (value.chars().anyMatch(c -> (c < 32 && c != '\t') || c == 127))
            throw new IllegalArgumentException("Invalid control character in renewal header: " + name);
    }
    private byte[] dechunk(byte[] body) {
        String text = helpers.bytesToString(body); int offset = 0;
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        while (true) {
            int end = text.indexOf("\r\n", offset);
            if (end < 0) throw new IllegalArgumentException("Invalid chunked renewal body.");
            int size;
            try { size = Integer.parseInt(text.substring(offset, end).split(";", 2)[0].trim(), 16); }
            catch (NumberFormatException ex) { throw new IllegalArgumentException("Invalid chunk size."); }
            offset = end + 2;
            if (size == 0) {
                if (!text.substring(offset).equals("\r\n")) throw new IllegalArgumentException("Chunk trailers cannot be converted by this API.");
                return decoded.toByteArray();
            }
            if (size < 0 || size > body.length - offset - 2 || !text.substring(offset + size, offset + size + 2).equals("\r\n"))
                throw new IllegalArgumentException("Invalid chunked renewal body.");
            decoded.write(body, offset, size); offset += size + 2;
        }
    }
}
