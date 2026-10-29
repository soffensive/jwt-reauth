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

Burp extension for independent authentication sessions, configurable renewal
requests, and cookie/header injection into scoped traffic. The interface has two
tabs: **Sessions** and **Debugging**.

## Session profiles

The **Sessions** tab supports independent accounts, cookies, and tokens. Each
profile owns its renewal request, extraction rules, schedule, and scope.

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
   changed, last success, and the next scheduled renewal.
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
unknown marker produce a log entry and no credentials are injected. For overlapping account scopes, use explicit markers. The extension
does not infer an account from the browser's existing cookies.

Up to four renewals can run concurrently, and a profile never overlaps its own
renewal. A successful HTTP 2xx response must contain every configured extracted
value; all values are published together. HTTP errors, malformed JSON, and
missing values preserve the previous snapshot and retry at the next interval.
Other profiles continue independently. Unchanged extraction rules retain their
latest values when a profile is edited, avoiding reuse of an expired bootstrap
token. Deleting or replacing a profile cancels its schedule and discards any
in-flight result. Use **Save profiles...** to persist configuration and current
values to a local JSON file.

The build bundles Gson and the validation API into the extension JAR; Burp's
API remains supplied by Burp. `gradle build` runs profile extraction, isolation, routing, persistence, protocol,
and concurrent-renewal checks.

## HTTP versions

Renewal supports HTTP/1.0, HTTP/1.1, and HTTP/2 through Burp's extension APIs.
The **HTTP protocol** setting defaults to **Automatic**: HTTP/1.1 templates use
Burp's normal protocol negotiation/settings; an HTTP/2 request line selects
Burp's HTTP/2 API, and an HTTP/1.0 request retains HTTP/1.0. Choose **HTTP/1** or
**HTTP/2** to explicitly override the template's protocol. A forced HTTP/2
request uses the HTTP/2 API without silently falling back to HTTP/1.

Burp's familiar text representation works for all these versions, including
`POST /refresh HTTP/2` or `HTTP/2.0`. For HTTP/2, the extension maps method, target,
Host, and scheme to pseudo-headers in Burp's expected order (`:scheme`, `:method`,
`:path`, `:authority`), lowercases header names, removes connection
headers, and recalculates body length. It preserves duplicate ordinary headers
and body bytes; multi-cookie headers are split into separate HTTP/2 cookie fields
to keep renewal requests representable in Burp's HTTP-style editor; chunked HTTP/1 bodies are decoded when converting to HTTP/2.
Cookie, header, JSON, and regex extraction works with either protocol's response
representation.

The Debugging tab identifies the selected transport (or automatic mode). In
automatic mode, the response's status line is also shown as returned by Burp.
These settings concern authentication renewal; ordinary traffic continues to
use the protocol selected by Burp's originating tool.

See [Burp's HTTP/2 support](https://portswigger.net/burp/documentation/desktop/http2)
and [extension HTTP APIs](https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html).

## Debugging requests and tokens

Open **Debugging** to inspect profile routing, injected headers and cookies,
removed profile markers, and reasons why credentials were not applied. Select an
event to compare the request before and after extension changes. The decision
view lists added/removed headers; renewal events include the HTTP response and
previous/current extracted values.

The **Current tokens and variables** view displays each profile's live values
in plain text, including the final prefixed headers/cookies. Profiles awaiting their first renewal are identified. Tokens are visible and copyable.

Use the text filter to find a profile, URL, or outcome. Disable **Follow latest**
to inspect an older event; **Clear history** removes recorded events without
changing profile values. History is held in memory and limited to 200 events;
each request/response detail view is truncated after 64 KiB for display only.

## Saving and loading profile files

Click **Save profiles...** in Sessions to save all profiles to a chosen JSON file.
The file includes renewal requests, endpoint/scope URLs, intervals, enabled and
automatic-selection settings, HTTP protocol, extraction rules, prefixes, original
initial values, and the latest extracted values. Saving those latest values lets
a rotated refresh token bootstrap the session after restarting Burp.

Click **Load profiles...** to restore profiles. New profiles are added; matching
names prompt before replacement, and other existing profiles remain unchanged.
The whole file is validated before any profiles are changed. Enabled profiles
resume their renewal schedule; disabled profiles stay disabled. Restored values
are used for renewal, but credentials are injected only after a successful new
renewal. Saving an empty profile list produces a valid empty file.

Files are versioned JSON (`schemaVersion: 1`) and contain credentials in plain
text. Save uses a temporary file and atomic replacement where supported. Debug
history is not saved. Saving is manual: later edits and token rotations require
another save to update the file; there is no automatic file loading on startup.

## Renewal request example

In the profile's HTTP editor, use a renewal variable named `refresh` in the body:

```http
POST /oauth/token HTTP/2
Host: example.test
Content-Type: application/x-www-form-urlencoded

refresh_token=${refresh}
```

Add a renewal-variable extractor with source **JSON**, selector `refresh_token`,
and the initial refresh token as its initial value. Add a header/token extractor
for `access_token` to inject `Authorization: Bearer ...` into scoped requests.
