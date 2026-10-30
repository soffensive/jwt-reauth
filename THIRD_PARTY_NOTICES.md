# Third-party notices

The release JAR includes the following unmodified runtime library. It remains
subject to its copyright notice and license. Its full license text is referenced
below and packaged in the JAR under `META-INF/licenses/`.

## Gson 2.10.1

- Maven coordinate: `com.google.code.gson:gson:2.10.1`
- Project: https://github.com/google/gson
- Attribution: Google and the Gson contributors.
- License: Apache License, Version 2.0.
- Local license text: `licenses/gson-2.10.1-LICENSE.txt`
- License source: https://github.com/google/gson/blob/gson-parent-2.10.1/LICENSE

## Compile-only dependencies

`net.portswigger.burp.extender:burp-extender-api:2.3` is used only to compile and
test the extension. It is not bundled in the release JAR; Burp Suite supplies the
API at runtime.

`javax.validation:validation-api:2.0.1.Final` (Apache License, Version 2.0) is used
only at compile time for `@NotNull` annotations and is not bundled in the release JAR.

## Project license

JWT Re-auth's own Apache 2.0 license is in `LICENSE.txt`. Upstream project
attribution and a description of the fork's changes are in `NOTICE`. These files
are also included under `META-INF/` in the release JAR. Existing dependency
license and notice resources are retained when runtime libraries are bundled.
