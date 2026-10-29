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

/** Run with java -ea after compiling alongside ReauthTemplate. */
public class ReauthTemplateTest {
    public static void main(String[] args) {
        String request = "POST /refresh HTTP/1.1\nHost: example.test\nCookie: sid=${session}\n\nrefresh=${refresh}";
        ReauthTemplate template = new ReauthTemplate(request,
                "session=(?im)^Set-Cookie: sid=([^;\\r\\n]+)\nrefresh=\"refresh_token\":\\s*\"([^\"]+)\"",
                "session=bootstrap\nrefresh=first");
        assert template.render().contains("Cookie: sid=bootstrap\r\n\r\nrefresh=first");
        template.extract("HTTP/1.1 200 OK\r\nSet-Cookie: sid=new; HttpOnly\r\n\r\n{\"refresh_token\":\"next$1\\value\"}");
        assert template.render().contains("Cookie: sid=new\r\n");
        assert template.render().endsWith("refresh=next$1\\value");
        template.extract("HTTP/1.1 500 Error\r\n\r\n");
        assert template.render().endsWith("refresh=next$1\\value");
        rejects(request, "", "session=one");
        rejects(request, "session=no-group", "session=one\nrefresh=two");
        rejects(request, "session=(", "session=one\nrefresh=two");
        rejects(request, "", "session=one\nsession=two");
        rejects("GET / HTTP/1.1\nHost: example.test", "", "");
        System.out.println("ReauthTemplate tests passed");
    }

    private static void rejects(String request, String rules, String initial) {
        try {
            new ReauthTemplate(request, rules, initial);
            throw new AssertionError("Expected invalid configuration to be rejected");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }
}
