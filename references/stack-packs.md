# Stack Packs

Read this in Phase 5 and Phase 6 for any language or platform which `stack-checks.md` does not cover. Each pack lists where flaws cluster, the first searches, and the attack moves. Version facts are not here. Look up each framework's current advisories with the procedure in `evidence-and-truth.md` and record source and date.

Regexes are leads. Trace each hit. Two patterns use lookahead and need PCRE mode (`rg -P`, or the Grep tool's PCRE option when it offers one). Team owners are in brackets.

## Contents
- [Python: Django, Flask, FastAPI](#python-django-flask-fastapi)
- [Java and JVM: Spring and others](#java-and-jvm-spring-and-others)
- [PHP: Laravel, WordPress, plain PHP](#php-laravel-wordpress-plain-php)
- [Ruby on Rails](#ruby-on-rails)
- [.NET](#net)
- [Rust and C or C++](#rust-and-c-or-c)
- [Mobile: Android and iOS](#mobile-android-and-ios)
- [Desktop: Electron and Tauri](#desktop-electron-and-tauri)
- [Browser extensions](#browser-extensions)
- [Serverless and edge functions](#serverless-and-edge-functions)
- [GraphQL](#graphql)
- [WebSocket, gRPC and real-time](#websocket-grpc-and-real-time)

## Python: Django, Flask, FastAPI

[T02, T03, T04, T08]

Flaws cluster in: debug mode and secrets in settings, raw SQL and `extra()`, template autoescape switched off, unsafe deserialization, `subprocess` with a shell, missing object-level checks in views and routers.

```
DEBUG\s*=\s*True|SECRET_KEY\s*=\s*['"]|ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]
\.(raw|extra)\(|cursor\.execute\([^)]*(%|\+|f['"]|\.format)
mark_safe\(|\|\s*safe\b|autoescape\s+off|Markup\(|render_template_string\(
pickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)|marshal\.loads|shelve\.open
subprocess\.(run|call|Popen|check_output)\([^)]*shell\s*=\s*True|os\.system\(
csrf_exempt|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True
```

Django: check `fields = '__all__'` or `exclude` in model forms and serializers (mass assignment), `permission_classes` missing or `AllowAny` on Django REST framework views, `queryset = Model.objects.all()` in viewsets with no `get_queryset` scoping, and admin exposed on a guessable path with weak accounts.

Flask: `app.run(debug=True)` reachable in production, session cookie secret literal, `send_file` or `send_from_directory` with user paths, no CSRF library.

FastAPI: routes without `Depends` for auth, `response_model` missing so full ORM rows leak, `allow_origins=["*"]` with credentials, background tasks which take user input into shell calls, docs and OpenAPI exposed publicly in production, Pydantic models with `extra = "allow"`.

Attack moves: change object ids against each view, call each API verb on each route, post extra fields to serializers, upload files with path tricks, send pickled or YAML payloads to any import feature, hit the debug page with an error.

## Java and JVM: Spring and others

[T02, T03, T04, T08]. Weakest language score in the Veracode 2026 report (30 percent). Spend extra time here.

Flaws cluster in: Spring Security filter chains with gaps, actuator exposure, deserialization, XML parsers, SQL and HQL string building, SpEL and template injection, path handling.

```
@PreAuthorize|@Secured|authorizeHttpRequests|antMatchers|requestMatchers|permitAll\(\)
management\.endpoints\.web\.exposure\.include\s*[:=]\s*(\*|.*(env|heapdump|beans|mappings))
ObjectInputStream|readObject\(|XMLDecoder|XStream|enableDefaultTyping|activateDefaultTyping
DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory
createQuery\([^)]*\+|createNativeQuery\([^)]*\+|Statement\.execute\w*\([^)]*\+
SpelExpressionParser|\.parseExpression\(|Velocity|Freemarker|Thymeleaf
new\s+File\([^)]*(getParameter|request|path)|Paths\.get\([^)]*(request|param)
csrf\(\)\.disable\(\)|\.csrf\(\w*\s*->\s*\w+\.disable\(\)\)
```

Check: `permitAll()` ordering (first match wins), method security enabled (`@EnableMethodSecurity`), actuator endpoints reachable without auth, XML parsers with external entities enabled, Jackson default typing, mass assignment through `@ModelAttribute` or entity binding with no DTO, and logging of user input without encoding (log injection).

## PHP: Laravel, WordPress, plain PHP

[T03, T04, T08]

```
\$_(GET|POST|REQUEST|COOKIE|FILES)\[[^\]]+\][^;]{0,80}(include|require|eval|exec|system|shell_exec|passthru|unserialize|file_get_contents|move_uploaded_file)
DB::raw\(|whereRaw\(|selectRaw\(|orderByRaw\(|->query\([^)]*\$
\{!!\s*\$|<\?=\s*\$[^;]*\?>(?!.*htmlspecialchars)
\$guarded\s*=\s*\[\s*\]|\$fillable\s*=\s*\[\s*['"]\*['"]
APP_DEBUG\s*=\s*true|display_errors\s*=\s*(On|1)
unserialize\(
```

Laravel: `APP_DEBUG=true` in production, `.env` reachable from the web root, mass assignment through empty `$guarded`, routes missing `auth` middleware or policies, `Storage::url` public disks for private files, queue and Horizon dashboards exposed.

WordPress: plugins and themes are the surface. List them with versions and look up each in a current vulnerability database. Check `wp-config.php` exposure, XML-RPC, REST user enumeration, `admin-ajax` actions without nonce and capability checks (`wp_ajax_nopriv_`), unsanitized `$wpdb->query` calls and file upload handlers in custom plugins.

Plain PHP: file inclusion with user input, upload into the web root, `register_globals` style variable overwrite, `extract($_POST)`.

## Ruby on Rails

[T03, T04, T08]

```
\.(where|order|group|having|joins|select)\(\s*["'][^"']*#\{
find_by_sql|connection\.execute\(
params\.permit!|permit\(\s*:?\w*\)?\s*\.\s*merge
html_safe|raw\(|<%==
skip_before_action\s*:(verify_authenticity_token|authenticate)
eval\(|instance_eval|constantize|Marshal\.load|YAML\.load\(
send\(params|public_send\(params
```

Check: strong parameters (`permit!` is a flag), `before_action :authenticate` coverage with `skip_before_action` clusters, `find(params[:id])` on unscoped models (use the current user's association), open redirects through `redirect_to params[:url]`, `secret_key_base` in the repo, and Active Storage public URLs. Brakeman covers part of this. Run it and trace its hits.

## .NET

[T02, T03, T04, T08]

```
\[AllowAnonymous\]|\[Authorize\]|\.RequireAuthorization\(|AddAuthorization
FromSqlRaw\(|ExecuteSqlRaw\(|SqlCommand\([^)]*\+|string\.Format\([^)]*SELECT
BinaryFormatter|NetDataContractSerializer|TypeNameHandling\.(All|Auto|Objects)|LosFormatter
XmlDocument|XmlReader|XmlTextReader|DtdProcessing\.Parse
Html\.Raw\(|@Html\.Raw|MarkupString
UseDeveloperExceptionPage|AllowAnyOrigin\(\)|ValidateAntiForgeryToken
```

Check: global authorization fallback policy (default-deny), model binding over-posting without view models, minimal API endpoints missing `RequireAuthorization`, `AllowAnyOrigin` with credentials, developer exception page in production, and Data Protection key storage in shared or ephemeral places.

## Rust and C or C++

[T04, T07]

Rust: memory safety removes whole classes. Search `unsafe` blocks, `unwrap()` and `expect()` on untrusted input in servers (panic as denial of service), `std::process::Command` with user strings, path joins with user input, and `serde` untrusted deserialization into permissive types. Run `cargo audit` or osv-scanner and read `build.rs` and proc-macro dependencies, since they run at build time.

C and C++: fixed buffers, `strcpy`, `sprintf`, `gets`, integer overflow in size math, format string misuse, use after free around callbacks, unchecked return values, signed and unsigned mixups, `system` and `popen` with user input.

```
\b(strcpy|strcat|sprintf|vsprintf|gets|scanf)\s*\(
\bsystem\s*\(|\bpopen\s*\(
printf\s*\(\s*[a-zA-Z_]\w*\s*\)
memcpy\s*\([^,]+,[^,]+,\s*[^)]*(len|size|n)\b
```

Use compiler sanitizers, fuzzing and static analyzers in the project's CI. Reading alone finds little here, so report the coverage limit.

## Mobile: Android and iOS

[T11, T06, T08]. Standards: OWASP MASVS and the MASTG testing guide. Check the OWASP mobile pages for the current versions.

Android flaws cluster in: exported components, intent handling, deep links, WebView settings, cleartext traffic, backup flags, secrets in resources, weak local storage, and debuggable builds.

```
android:exported="true"
android:allowBackup="true"|android:debuggable="true"|usesCleartextTraffic="true"
setJavaScriptEnabled\(true\)|addJavascriptInterface|setAllowFileAccess\(true\)|setAllowUniversalAccessFromFileURLs
MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getExternalStorage
TrustManager|HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|onReceivedSslError
```

iOS flaws cluster in: ATS exceptions, URL scheme and universal link handling, keychain accessibility, `UserDefaults` for secrets, WebView settings, pasteboard use, and logging of sensitive values.

```
NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads
kSecAttrAccessibleAlways|UserDefaults\.standard\.set\([^)]*(token|password|secret)
evaluateJavaScript|WKUserContentController|allowsInlineMediaPlayback
NSLog\(|print\([^)]*(token|password)
```

Cross-cutting: API keys in the binary are public (decompile and read strings), certificate pinning bypasses are routine for a motivated attacker so treat pinning as friction only, and the server must repeat every check the app makes. The mobile API often lags the web API in authorization, so compare them (S04). Static reading cannot confirm runtime behavior. Say so in the coverage record.

## Desktop: Electron and Tauri

[T11, T08]

Electron flaws cluster in: `nodeIntegration`, missing `contextIsolation`, `webSecurity: false`, remote content with preload access, unsafe IPC handlers, `shell.openExternal` with user URLs, and outdated Chromium.

```
nodeIntegration\s*:\s*true|contextIsolation\s*:\s*false|webSecurity\s*:\s*false
allowRunningInsecureContent|enableRemoteModule|sandbox\s*:\s*false
shell\.openExternal\(|ipcMain\.(handle|on)\(
loadURL\(\s*['"`]?https?:|loadURL\([^)]*(req|param|url)
```

Check every IPC handler as an API endpoint: validate the sender frame, validate arguments, and give each handler the least power. Check the auto-updater for signature verification and an HTTPS source. Tauri: read the allowlist or capability files for broad filesystem, shell and HTTP scopes.

## Browser extensions

[T11, T07]

Read `manifest.json` first: requested permissions, host permissions, content scripts and their match patterns, `web_accessible_resources`, `externally_connectable`, and the content security policy.

```
"permissions"|"host_permissions"|"<all_urls>"|"\*://\*/\*"
"web_accessible_resources"|"externally_connectable"|unsafe-eval|unsafe-inline
chrome\.(tabs|cookies|webRequest|scripting|storage)\.|browser\.(tabs|cookies|webRequest)
innerHTML|eval\(|new Function\(|postMessage\(
```

Check: broad host permissions where a few hosts would do, message handlers which trust page messages, content scripts which inject page-controlled HTML, remote code loading (not allowed by store policy, and still a flaw), and tokens kept in storage readable by content scripts. An extension runs with the user's logged-in sessions, so a flaw has a large blast radius.

## Serverless and edge functions

[T03, T08, T12]

Flaws cluster in: public function URLs with no auth, over-broad execution roles, secrets in environment variables shared across functions, no concurrency or spend limits, trusting headers set by the platform in the wrong layer, and functions which proxy to internal services.

Check: every function's trigger and who is able to invoke it. The execution role per function. Concurrency, timeout and memory limits. Whether a cold-start or retry duplicates a side effect (idempotency). Whether the function trusts `X-Forwarded-*` or identity headers a client is able to set. For platform functions with their own JWT verification toggles, confirm the code authorizes the caller when the toggle is off (`baas-supabase-firebase.md`).

## GraphQL

[T03, T04, T12]

Moves: run introspection and read the whole schema, query deeply nested relations to cross object boundaries, batch many operations in one request to defeat per-request limits, use aliases to repeat one expensive field, request fields the UI never uses, send mutations with extra input fields, and subscribe without authorization.

```
introspection\s*[:=]\s*true|playground\s*[:=]\s*true|graphiql
depthLimit|queryComplexity|costAnalysis|maxDepth
@UseGuards|@Authorized|@auth|shield\(|rule\(
```

Check: authorization at the field and resolver level, not only at the route. Depth and cost limits. Introspection and the IDE off in production. Batching and alias limits. Per-object checks in nested resolvers, since a parent check does not cover children.

## WebSocket, gRPC and real-time

[T02, T03, T12]

Moves: connect with no token and see what the server sends, authenticate once and keep an expired token alive, subscribe to another user's channel by id, send oversize or malformed frames, flood messages, and reuse a connection across tenants.

Check: authentication on the upgrade request and again per channel or topic. Origin checks on WebSocket upgrades (cross-site WebSocket hijacking). Message size and rate limits. Authorization on each message type, not only on connect. For gRPC: interceptors for auth, reflection disabled in production, and TLS between services.
