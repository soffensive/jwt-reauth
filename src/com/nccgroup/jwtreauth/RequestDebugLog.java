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

import java.time.Instant;
import java.util.*;

/** Bounded, thread-safe history; observers poll it from the Swing event thread. */
public final class RequestDebugLog {
    public static final int MAX_EVENTS = 200;
    public static final int MAX_TEXT = 65536;
    public static final class Event {
        public final long id;
        public final Instant time = Instant.now();
        public final String kind, profile, url, reason, before, after, response, details;
        public final boolean changed;
        private Event(long id, String kind, String profile, String url, String reason,
                      String before, String after, String response, String details) {
            this.id = id; this.kind = kind; this.profile = profile; this.url = url;
            this.reason = reason; this.changed = !kind.equals("Renewal") && !Objects.equals(before, after);
            this.before = limit(before); this.after = limit(after); this.response = limit(response); this.details = limit(details);
        }
    }
    private final Deque<Event> events = new ArrayDeque<>();
    private long sequence, revision;
    public synchronized void add(String kind, String profile, String url, String reason,
                                 String before, String after, String details) {
        append(new Event(++sequence, kind, profile, url, reason, before, after, "", details));
    }
    public synchronized void addRenewal(String profile, String url, String reason, String request, String response, String details) {
        append(new Event(++sequence, "Renewal", profile, url, reason, request, "", response, details));
    }
    private void append(Event event) {
        events.addLast(event);
        while (events.size() > MAX_EVENTS) events.removeFirst();
        revision++;
    }
    public synchronized List<Event> snapshot() { return new ArrayList<>(events); }
    public synchronized long revision() { return revision; }
    public synchronized void clear() { events.clear(); revision++; }
    private static String limit(String value) {
        if (value == null) return "";
        return value.length() <= MAX_TEXT ? value : value.substring(0, MAX_TEXT) + "\n[Display truncated at 64 KiB]";
    }
}
