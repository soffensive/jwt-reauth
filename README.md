# JWT Re-auth

Burp extension for renewing multiple authentication sessions and injecting their
cookies or tokens into scoped requests. Supports HTTP/1.0, HTTP/1.1, and HTTP/2.

[soffensive's fork](https://github.com/soffensive/jwt-reauth) of
[NCC Group's JWT Re-auth](https://github.com/nccgroup/jwt-reauth).
Modified in this fork (2026): independent session profiles, custom renewal
requests, response extraction, request debugging, and local profile files.

## Getting started

Load the extension JAR through Burp's **Extensions → Installed → Add → Java**.
To build from source, use JDK 17 or newer: `./gradlew build`. The wrapper downloads
Gradle 9.8.2. The JAR targets Java 17, is written to `releases/`, and the build also
runs the automated checks.

1. In **Sessions**, click **New profile**, or right-click a captured request and
   choose **Send to JWT re-auth (create session profile)**.
2. Set a name, renewal URL, interval, and **Modify requests**: **In scope (no
   marker)** or **With marker, in scope**. Edit the renewal request in Burp's HTTP editor and the requests to
   modify in the **Scope** tab. The overview summarizes each profile's mode and scope.
3. Add extractors, supply any initial values needed for the first renewal, and
   click **Save and test**.
4. Check **Active** for the profile directly in the Sessions overview to start
   renewal and credential injection. Uncheck it to stop both. New profiles start
   inactive; **Save and test** or **Renew now** can test them without activation.
   Token values are retained when toggling; injection requires a successful renewal.

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

## Selecting requests to modify

Each profile uses one mode, shown in the overview's **Match by** and **Applies
to** columns:

- **Scope:** modifies unmarked requests within the profile's scope. Exactly one
  active Scope profile must match.
- **Marker:** modifies requests containing the profile's marker, for example
  `X-Reauth-Profile: alice`. Requests must also fall within the profile's scope.
  The overview shows both the marker and the scope.

Scope rules apply in both modes; the mode only decides whether a marker is
required.

The **Scope** tab holds a table of rules, each with an action, a match type, and
a URL:

- **INCLUDE** rules add requests; **EXCLUDE** rules remove them and always win,
  for example include `https://example.test/api` but exclude
  `https://example.test/api/logout`.
- **PREFIX** matches the URL's path and everything below it on a segment
  boundary: `/api` matches `/api/users`, but not `/apievil`. **EXACT** matches
  the path only. Both ignore query strings.
- Scheme, host, and port must always match the rule's URL.
- **Also include Burp target scope** adds every URL in Burp's **Target → Scope**.
  Exclusions still apply. A profile needs at least one include rule or this option.
- Paths with `.` or `..` segments (including `%2e`) never match.

The extension strips marker headers before forwarding. Unknown markers,
conflicting matches, and markers naming a Scope profile inject no credentials.
Accounts are not inferred from existing browser cookies.

## Debugging

The **Tokens** tab shows current tokens and variables for all profiles in plain
text. Long values wrap instead of scrolling. **Copy value** copies the raw value;
**Copy header** / **Copy cookie** copy it as sent, for example
`Authorization: Bearer …`. It updates independently of debug history.

The **Debugging** tab shows routing decisions and request changes. Requests no
profile matches are recorded only when **Log unmatched requests** is checked. Ordinary
requests use Burp's standard before/after viewers; renewal events show the renewal
request and response instead, including failed responses. Select an event to
inspect its exchange and details.

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

## Login and refresh workflows

The profile editor has **Refresh request**, **Login request (optional)**, and
**Scope** tabs. Right-click a captured login request and choose **Send to JWT re-auth (set login
request)**, then select an existing profile or create a new one. The editor opens
on the login tab with its URL and request populated. Alternatively, check
**Use login before refresh** and enter the URL and request manually. Click
**Save and test** to test the workflow. To bootstrap a session:
login runs until it succeeds, then subsequent renewals use the refresh request.
Both steps use the profile's extraction rules and protocol selection. A rule
whose value is absent from a response keeps its previous value, so login and
refresh responses may carry different fields; a step fails only when no rule
matches. Values containing line breaks are rejected. Leave the login request
blank for refresh-only operation. Imported profiles run login again when
configured. If a refresh fails, the next attempt runs login again, then refresh
resumes after it succeeds. Requests to the login URL never receive injected
credentials.

Login settings and scope rules are included in profile files. Files saved by
earlier versions still load: their scope URL and `SUBTREE` lines become INCLUDE
PREFIX rules, and `EXACT` lines become INCLUDE EXACT rules.

To update a refresh request, right-click it in Burp and choose **Send to JWT
re-auth (set refresh request)**. Select an existing profile or create a new one;
the Refresh tab opens with the request and destination URL populated. Existing
login settings and extraction rules are retained until you save your edits.
