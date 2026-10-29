# JWT Re-auth

Burp extension for renewing multiple authentication sessions and injecting their
cookies or tokens into scoped requests. Supports HTTP/1.0, HTTP/1.1, and HTTP/2.

[soffensive's fork](https://github.com/soffensive/jwt-reauth) of
[NCC Group's JWT Re-auth](https://github.com/nccgroup/jwt-reauth).
Modified in this fork (2026): independent session profiles, custom renewal
requests, response extraction, request debugging, and local profile files.

## Getting started

Load the extension JAR through Burp's **Extensions → Installed → Add → Java**.
To build from source, use Java 11 and Gradle 7.1: `gradle build`. The JAR is written
to `releases/`; the build also runs the automated checks. This checkout does not
include the wrapper JAR, so use an installed Gradle rather than `./gradlew`.

1. In **Sessions**, click **New profile**, or right-click a captured request and
   choose **Send to JWT re-auth (create session profile)**.
2. Set a name, renewal URL, scope URL, and renewal interval. Edit the renewal
   request in Burp's HTTP editor. Scope matches the URL's scheme, host, port, and
   path subtree: `/api` includes `/api/users`, but not `/apievil`.
3. Add extractors, supply any initial values needed for the first renewal, and
   click **Save and test**.
4. Enable **Renew and inject automatically** to renew on schedule and inject
   credentials. Injection starts after a successful renewal.

The **HTTP protocol** setting defaults to automatic selection using Burp's
settings and the request version. Select **HTTP/1** or **HTTP/2** to override it.

## Extracting cookies and tokens

| Button | Default extraction | Used as |
| --- | --- | --- |
| **Add cookie** | Named cookie from `Set-Cookie` | Request cookie |
| **Add header / token** | JSON field `access_token` | `Authorization: Bearer …` |
| **Add renewal variable** | JSON field `refresh_token` | `${refresh}` in the next renewal |

Each extractor supports **COOKIE**, **HEADER**, **JSON**, or **REGEX**. JSON uses
dotted object paths, such as `data.access_token`; regex uses its first capture
group. Destinations and value prefixes are configurable.

For example, define a JSON renewal variable named `refresh`, then use it here:

```http
POST /oauth/token HTTP/2
Host: example.test
Content-Type: application/x-www-form-urlencoded

refresh_token=${refresh}
```

Variables are inserted literally; apply any encoding your endpoint requires.
A successful renewal must return HTTP 2xx and every configured extracted value.
Failed renewals retain the previous values and retry at the next interval.
Profiles renew independently, without overlapping their own requests.

## Selecting a session

For multiple accounts on the same application, add a profile marker:

```http
X-Reauth-Profile: alice
```

The extension removes the marker before forwarding. The named profile must be
enabled and match the request's scope.

Alternatively, enable **Select by scope without a marker**. Exactly one enabled
profile must match; ambiguous matches and unknown markers inject no credentials.
Accounts are not inferred from existing browser cookies.

## Debugging

The **Debugging** tab shows routing decisions, renewal responses, and request
changes in Burp's standard before/after viewers. **Current tokens and variables**
shows live credential values in plain text.

Filter events, disable **Follow latest** to inspect an older request, or use
**Clear history**. History holds 200 events, with each message/detail view limited
to 64 KiB for display.

## Profile files

Use **Save profiles...** and **Load profiles...** to store settings and current
extracted values as JSON. Loading adds profiles and prompts before replacing
matching names. Enabled profiles resume renewal; credentials are injected only
after a successful new renewal.

Files contain requests and credentials in plain text. Saving is manual: save
again after edits or token rotations. Files are not loaded automatically, and
debug history is not saved.

## License

[Apache License 2.0](LICENSE.txt). Original copyright 2022 NCC Group; original
contributors are listed in [CONTRIBUTORS.md](CONTRIBUTORS.md). This fork is
independently maintained and not endorsed by NCC Group.

See [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for
attribution and bundled dependency licenses, also included in the release JAR.
