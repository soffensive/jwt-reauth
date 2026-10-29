# JWT Re-auth

This is [soffensive's modified fork](https://github.com/soffensive/jwt-reauth) of
[NCC Group's JWT Re-auth](https://github.com/nccgroup/jwt-reauth), originally
copyright 2022 NCC Group. The original contributors are listed in
[CONTRIBUTORS.md](CONTRIBUTORS.md). This fork is independently maintained and is
not endorsed by NCC Group.

Modified in this fork (2026): custom re-authentication request templates,
response-variable extraction, independent concurrent session profiles, a Sessions
UI, automated checks, and release packaging with license notices. The screenshots
below show the original UI; the Sessions tab is described further down.

## License and attribution

This fork is distributed under the [Apache License 2.0](LICENSE.txt). Original
copyright and attribution notices are retained; modified source files identify
the fork's changes. See [NOTICE](NOTICE) for project attribution and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for bundled dependencies and their
license texts. The release JAR includes these documents under `META-INF/`, with
dependency license texts under `META-INF/licenses/`.

Burp plugin to cache authentication tokens from an "auth" URL, and then add them as headers on all requests going to a certain scope.

## Features

The plugin allows settings to be sent to it via context menus from various menus.
This includes using an entire captured request to acquire new authentication tokens.

![Screenshot showing a drop-down context menu inside of burpsuite, with the text "Send to JWT re-auth (set auth token)"](images/send-to-extension.png)

All of the settings for the plugin can be controller from the main UI panel:

![Screenshot showing the main UI, it has several rows of settings, with a name next to a text box describing each setting.
Then there are three, rows showing the state of the listener and most recently parsed tokens, with a button to copy the token.
In the bottom third of the screen there is a log showing events from the plugin, as well as buttons to filter them and a search box.](images/ui.png)

There is a seperate UI panel to show the scope:

![Screenshot showing a mostly empty panel with a drop-down spinner to filter the scope items, a search box,
and below that, one row showing a in-scope URL, and an empty row.](images/scope.png)

Finally we can see the plugin attaching a cached authentication token as a header.

![Screenshot shows firefox open with a webpage listing the headers sent to the site, one can be seen called Authorization, which holds the cached auth token.](images/demo.png)
## Session profiles

The **Sessions** tab supports independent accounts, cookies, and tokens. The
older single-session configuration is available under **Legacy settings**.

1. Right-click a captured request in Burp and select **Send to JWT re-auth
   (create session profile)**, or click **New profile** in the Sessions tab.
2. Name the profile, for example `alice`. Set its renewal URL and scope URL.
   Scope matches the same scheme, host, and port, and a path subtree: `/api`
   includes `/api/users` but excludes `/apievil`. The renewal URL sets the
   destination service; the HTTP editor sets the actual method, path, and body.
3. Click **Add cookie** and enter the cookie name. The extension extracts that
   cookie from `Set-Cookie` and replaces that cookie in matching outgoing
   requests while preserving unrelated cookies. No regex is needed.
4. For a bearer token, **Add header / token** defaults to JSON field
   `access_token`, destination header `Authorization`, and prefix `Bearer `.
   JSON selectors support dotted object paths, such as `data.access_token`.
   Header extraction uses a response header name; advanced regex extraction
   uses its first capture group and searches headers and body.
5. To rotate a refresh token, click **Add renewal variable**. Set its initial
   value and put `${refresh}` in the renewal request. All extracted variables
   can be used as placeholders. Values are inserted literally; apply the
   encoding required by your endpoint. Initial values can be blank unless the
   first renewal needs a bootstrap value.
6. Click **Save and test**. The table reports success/failure, which variables
   changed (values are masked), last success, and the next scheduled renewal.
   Enable **Renew and inject automatically** to schedule renewal and allow
   credential injection. A disabled profile can be tested without injecting.

For two accounts on the same application, create profiles `alice` and `bob`.
Add a header to each request to select its account explicitly:

```http
X-Reauth-Profile: alice
```

The extension removes this header before forwarding, including when the name
is unknown. Explicit selection still requires an enabled profile and matching
scope, so a marker cannot send credentials outside the configured destination.
Requests need a successful renewal before profile credentials are injected.

Alternatively, enable **Select by scope without a marker**. Automatic selection
only applies when exactly one enabled profile matches. Multiple matches or an
unknown marker produce a log entry and no profile or legacy credentials are
injected. For overlapping account scopes, use explicit markers. The extension
does not infer an account from the browser's existing cookies.

Up to four renewals can run concurrently, and a profile never overlaps its own
renewal. A successful HTTP 2xx response must contain every configured extracted
value; all values are published together. HTTP errors, malformed JSON, and
missing values preserve the previous snapshot and retry at the next interval.
Other profiles continue independently. Unchanged extraction rules retain their
latest values when a profile is edited, avoiding reuse of an expired bootstrap
token. Deleting or replacing a profile cancels its schedule and discards any
in-flight result. Profile configuration and secrets are held in memory only.

The build bundles Gson and the validation API into the extension JAR; Burp's
API remains supplied by Burp. `gradle build` runs the template checks and
profile extraction, isolation, routing, and concurrent-renewal checks.

## Custom re-authentication requests

Set **Authorization URL** to the authentication endpoint, then open **Edit custom
request / response variables...**. Paste a complete HTTP request, including the
blank line between headers and body. The URL supplies the destination host, port,
and TLS setting; the template supplies the method, path, headers, and body.
Requests captured using **set auth request** also populate the editor.

Use `${name}` anywhere in the request to insert a response variable. For example:

```http
POST /oauth/token HTTP/1.1
Host: example.test
Content-Type: application/x-www-form-urlencoded
Cookie: session=${session}

refresh_token=${refresh}
```

Define response extractors, one `name=regex` per line:

```text
refresh="refresh_token":\s*"([^"]+)"
session=(?im)^Set-Cookie: session=([^;\r\n]+)
```

Each regex searches the complete response (headers and body) and stores its first
capture group. Provide initial values for all request placeholders:

```text
refresh=initial-refresh-token
session=initial-session-cookie
```

After each authentication response, extracted values replace the initial values
for subsequent refresh requests. Missing matches retain the previous value.
Substitution is literal: apply any URL or JSON escaping your endpoint requires.
Content-Length is recalculated when the request is built. The existing **Token
regex**, header settings, and scope still control access-token injection into
ordinary requests.

Saving the template schedules a refresh and stops listening; enable **Listening**
to resume scoped header injection and periodic refreshes. Changing Authorization
URL or selecting another captured auth request clears the active custom template.
Save the editor again to activate it for the new URL. Saving a blank request
restores the default GET request. Configuration and extracted variables are held
in memory for the current extension session.

To run the dependency-free template checks (Java 11 or later):

```sh
javac -d /tmp/jwt-reauth-tests src/com/nccgroup/jwtreauth/ReauthTemplate.java tests/com/nccgroup/jwtreauth/ReauthTemplateTest.java
java -ea -cp /tmp/jwt-reauth-tests com.nccgroup.jwtreauth.ReauthTemplateTest
```
