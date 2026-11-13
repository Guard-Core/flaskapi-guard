Release Notes
=============

___

Unreleased
----------

- **Fixed** - **A view decorated by a different `SecurityDecorator` is reported at the first request (release note, behavior change).** A view whose route id the extension's decorator does not know was decorated by another `SecurityDecorator` instance, so none of its decorators applied, and the check of the URL map skipped it without a word. The first request now reports it with guard-core's `route.unknown_to_decorator` kind: with `fail_on_misconfiguration=True` every request is refused with a fresh `MisconfigurationError` until the view uses the extension's decorator, with it off one WARNING is logged per view. A decorator that was created and decorated nothing, and a route that uses the middleware's decorator, are not reported.

- **Changed** - **`fail_on_misconfiguration` now governs the first-request report of a `detection_exclusion(path_params=...)` problem (release note, behavior change).** The first request used to log one WARNING whatever the flag said. Flask has no hook after route registration and refuses new routes once it has handled a request, so the first request is the earliest point every route exists: with `fail_on_misconfiguration=True` that request, and every request after it, now raises a fresh engine error built from the cached result (a `ValueError` listing every problem; Flask answers 500 unless exceptions propagate) and the list is logged once. With the flag off the first request logs one WARNING per problem, as before. Each problem carries a stable kind, `decorator.detection_exclusion.param_not_in_template` or `decorator.detection_exclusion.param_without_literal_segment`, from one guard-core helper that every adapter shares.

- **Added** - **`release_app(config)` is the host and test API for releasing an app.** Flask has no app-shutdown event (`teardown_request` and `teardown_appcontext` run on every request), so `FlaskAPIGuard` never releases its app by itself and N requests through an app leave the module-level default binding as it was. A host that stops an app, and a test suite that builds several apps, call `flaskapi_guard.release_app(config)` (guard-core's sync `release_app`, now re-exported) with the `SecurityConfig` the app was built with; the default managers then go to the next app at that moment instead of whenever the cyclic garbage collector frees the earlier app. An app that is never released keeps the collector-timed handoff of guard-core 5.0.0. Calling it twice is harmless, and a request that reaches a released app is still screened with the managers its pipeline captured at build time. Never call it from `teardown_request` or `teardown_appcontext`: it would release a live app on every request. The suite's `tests/conftest.py` releases every app's config between tests.

- **Fixed** - **The `guard-core` floor is `>=5.0.0,<6`.** This release's code uses engine names that guard-core 4.4.x does not have, so an environment that kept 4.4.x imported a broken package. Upgrading now installs guard-core 5.x and stops below the next major. An install that must stay on guard-core 4.x stays on the previous release of this package. The lock follows the floor once guard-core 5.0.0 is published.

- **Fixed** - **Every shipped dependency declares a lower bound with no known advisory.** The declared floors are now `flask>=3.1.3`, `werkzeug>=3.1.9` and `gunicorn>=22.0.0` (none had a lower bound; the first two are the first releases with no advisory against them). An app pinned below Flask 3.1.3 or Werkzeug 3.1.9 must move up to them. The suite passes with every direct dependency at its floor on Python 3.10 and 3.11.

- **Fixed** - **The lock moved past every known advisory and the supply chain is pinned.** The lock moves `certifi` to 2026.10.18, `joserfc` to 1.7.6 and `nltk` to 3.10.4; no declared floor changes. A new CVE gate (`cve-scan.yml`, run on every pull request, push, daily and before a release) fails on any open advisory in the lock, in the declared dependency floors and in the published image, and every workflow action and tool install is pinned to a commit or version.

- **Fixed** - **A scan that only waited for a regex worker answers 503 with `Retry-After`, not 400.** With 64 uploads in flight on Flask and Django, guard-core 5.0.0 refused 1 to 4 of 64 benign 1 MiB uploads: a scan that got no regex worker within `detection_compiler_timeout` answered `400 Request body could not be read`, and a started scan that waited for the GIL past that time was refused as `400 Suspicious activity detected` with a strike. guard-core now runs its six windowed built-in rows on the request thread, judges a started custom scan by its worker's CPU, and answers a scan that got no worker in time with `503` and `Retry-After` set to `ceil(detection_compiler_timeout)`, no strike, and its own log line and event naming the wait and the surface. `custom_error_responses[503]` replaces the message, a real body read failure keeps its `400`, and `fail_secure=False` and passive mode pass with the event. `flaskapi-guard` carries a test that holds the regex pool busy and checks the `503`, the `Retry-After` header and the custom message.

- **Fixed** - **`api/security-middleware.md` states what the code measures instead of '< 200 LOC' and '2-3x faster feature additions (projected)'.** Of the 69 modules under `guard_core/sync/core/`, 51 are 200 lines or shorter and 18 are longer (the largest is 798 lines), and the 18 checks written so far take 35 to 512 lines each. The page now names the command that counts the lines, and it no longer states a speed-up that no measurement backs.

- **Fixed** - **The detection engine pages state numbers measured on guard-core 5.0.0, each with the command that reproduces it.** The 'Latency Impact' and 'Memory Usage' sections of `architecture.md` and the benchmark section and checklist of `performance-tuning.md` carry CPU time per call (interleaved with an A/A arm) and Python heap and RSS per step in place of the old estimates (`< 1ms` preprocessing, `1-5ms` semantic analysis, `5-20ms` total detection, `~100KB`, `~1MB` and `~2-5MB`), measured with `python -m perf_gate.detection_components` from a guard-core checkout. The measurements corrected three remarks: capture groups cost nothing measurable on the example pattern, a higher `detection_semantic_threshold` does not make detection faster (the CPU is the same at 0.6, 0.7 and 0.8), and `detection_max_content_length=2000` cuts the CPU of a 10,000-character value by 25%. The checklist lists the pattern validation cache hit rate, which guard-core 5.0.0 reports through `get_cache_stats()`: 0.0 at the first boot and 1.0 at the second for 20 custom patterns.

- **Fixed** - **Every shipped Markdown example and stated default matches the 5.0.0 API, and a test keeps it true.** `tests/test_markdown_python_blocks.py` parses every Python block of the README, `docs/`, the examples and the packaged skill files, runs the blocks of each file one after another in a sandbox with no network, and checks every Guard import, call, keyword and attribute against the installed guard-core 5.0.0 objects. It also compares every default and range a table or bullet states with `SecurityConfig`, checks the documented signature listings, and checks the telemetry mute values against the engine. It failed on the old pages, and the pages now show what 5.0.0 accepts: `SecurityConfig` keywords that do not exist (`rate_limit_requests`, `enable_https`, `log_level`), `FlaskAPIGuard.configure_cors` and `SusPatternsManager.clear_custom_patterns` (neither exists), `flaskapi_guard.utils.detect_penetration_attempt` (the function is `guard_core.sync.utils.detect_penetration_attempt`, takes a `FlaskGuardRequest` and returns a `DetectionResult`), `log_activity` called with the raw Flask request, and `app.extensions["flaskapi_guard"].redis_handler` (the extension sits under the `"guard"` key); country decorators and return monitors shown without the geo source and the response body scanning 5.0.0 requires, `block_user_agents` patterns such as `.*bot.*` that the ReDoS validator refuses, custom patterns that `add_pattern` rejects, `blocked_countries` set together with `whitelist_countries`, `Cloudflare` as a cloud provider, custom GeoIP handler and Redis protocol listings that left out members, `avg_execution_time` where the pages said `average_time`, the detection engine component pages (module paths, constructors, methods and result shapes), the check order (up to 18 checks), the telemetry mute values, and stale defaults (`rate_limit` 120, `enable_redis` off unless a Redis field is set, `redis_prefix` `guard_core:`, `trust_x_forwarded_proto` `False`, `Cross-Origin-Resource-Policy` `same-site`, no `Cross-Origin-Embedder-Policy`, Python 3.10 to 3.15). The packaged skill file no longer says it is current for an older release, that `enable_redis` defaults to `True`, or that the default limit is 10 requests per 60 seconds.

- **Fixed** - **The packaged agent skill file shows a route example that runs.** `flaskapi_guard/.agents/skills/flaskapi-guard/SKILL.md` used `@security.configure(RouteConfig(...))`, a method no decorator has, and built `SecurityDecorator()` without its config. It now builds `SecurityDecorator(config)`, registers it with `guard.set_decorator_handler(security)` and stacks `@security.rate_limit`, `@security.require_https` and `@security.require_ip`. A new test runs every Python block of the packaged skill files against a Flask app, so a renamed or missing API fails the suite.

- **Breaking changes** - **A country rule or geo rate limit with no geo source now raises when the route is declared.** `@block_countries`, `@allow_countries` and `@geo_rate_limit` raise `ValueError` at import (so the app does not start) when the decorator's config has neither `geo_ip_handler` nor `ipinfo_token`, or has `ipinfo_token` without the `maxminddb` package and `requests`, as long as `fail_on_misconfiguration` is `True` (the 5.0.0 engine default). Before, the app started and every request answered 500 from the first-request initialization. Flask has no hook after route registration, so the declaration is the earliest point; `fail_on_misconfiguration=False` starts and logs the warning once at the first request. A decorator built from a config without a geo source and paired with an extension config that has `ipinfo_token` now raises at import: give the decorator's config the token. Needs the guard-core release that carries the declaration check.

- **Fixed** - **Country rules need no global rule.** The extension keeps `config.geo_ip_handler` whenever one is configured and reads back the handler the sync engine runs with: a handler built from `ipinfo_token` is now the synchronous `IPInfoManager`, so `blocked_countries` blocks (it never did, the engine called the async manager without awaiting it), and a route-level `block_countries`, `allow_countries` or `geo_rate_limit` works without a global country rule. The examples no longer carry a placeholder `blocked_countries`.

- **Fixed** - **The extension runs the engine's check order.** It builds its pipeline with the engine's `build_default_pipeline` instead of a list of its own, so the order is the engine's and a later engine change reaches it. IP security, cloud, user agent and rate limiting now run before `required_headers`, `authentication`, `referrer`, `custom_validators` and `time_window`: a banned IP that also lacks a required header gets the ban answer, and a request over the rate limit that also fails authentication gets `429`. The `cors_preflight` check now runs in the engine's position, between `user_agent` and `rate_limit`. The startup log line is unchanged in form, and the pipeline holds only the checks the config and the registered routes need, as in fastapi-guard.

- **Breaking changes** - **The base install no longer carries `redis`, `maxminddb`, `aiohttp` or `requests`.** They follow guard-core 5.0.0, whose base install is `cachetools`, `pydantic` and `typing-extensions`. `flaskapi-guard` gains three extras that forward to guard-core's: `flaskapi-guard[redis]` (the Redis client, needed when Redis is on), `flaskapi-guard[geo]` (`maxminddb` and the downloader of the built-in GeoIP manager, needed for country rules) and `flaskapi-guard[cloud]` (`aiohttp` and `requests`, needed for cloud-provider blocking). A config that needs a package you did not install is refused when `SecurityConfig` is built, with a message that names the adapter's extra, and the Redis, cloud, geo and rate-limit names the package re-exports load lazily, so the import works without them. Add the extra your config uses, for example `pip install "flaskapi-guard[redis,geo]"`.

- **Added** - **The route gate: the extension records the matched route template and answers `static_file_exists`.** `_populate_guard_state` records the matched rule's template (`request.url_rule.rule`) as `g.guard_route_template` next to `guard_route_unresolved`, which guard-core's route gate reads: a script path such as `/shop/cart.php` is clean only when the rule literally contains its extension, and a `<path:name>` converter does not. A `.ts` or `.map` path served by the application's or a blueprint's static endpoint is clean when `werkzeug.utils.safe_join` keeps it inside the static folder and the file exists (the URL map is asked, so a catch-all route is not a static mount, and nothing is cached); a redirect, a missing route, a traversal and a null byte keep the path flagged as in 4.4.0. The extension also lists its static route prefixes (`static_route_prefixes()`) so guard-core can warn once about an `exclude_paths` entry that matches no route.

- **Changed (behavior)** - **`endpoint_rate_limits` keys follow the Flask router, and every routed view has a handler identity.** Each key is resolved through the app's URL map at startup and when a dynamic rule is applied, so a key counts the requests that reach the same view with the same path parameters, and a key that matches no rule falls back to a normalized match (`//` collapsed, dot segments resolved, one trailing slash stripped, case kept). The extension sets the handler identity for every routed view, decorated or not, so `rate_limit` buckets key by the route and an undecorated view is found by its rules. Two paths stacked on one view share one budget (`@app.route("/login")` and `@app.route("/signin")` on one view count against one limit, so a stacked path cannot get a fresh budget), and a generic view stacked on many paths shares one too, so give each limited path its own view.

- **Added** - **Request bodies are read with an idle deadline from the server's socket.** `FlaskGuardRequest.read_body_prefix_until_idle(max_bytes, idle_timeout)` reads at most `max_bytes` from `request.stream` in chunks and maps a socket timeout, including the one Werkzeug wraps in `ClientDisconnected`, to `BodyReadStalledError`. Where the server exposes its socket in the WSGI environ (`werkzeug.socket`, `gunicorn.socket`) the read sets the idle timeout on it and restores the old one; on any other server (`wsgiref` with its handler timeout, uWSGI harakiri) the server's own socket timeout is the deadline. A client that sends headers and no body gets `408` under `fail_secure` (a log line and a `suspicious_request` event, no strike) and a slow client that keeps sending gets through. The bytes the read consumed are replayed, so the view still reads the whole body.

- **Changed (behavior)** - **Throttle rules answer `429`, route and global, unrouted paths included.** The adapter called `process_usage_rules` as a bare statement and dropped the refusal it returned, so a usage `throttle` rule recorded its trips and never refused. It now answers the engine's `429 Too many requests` with `Retry-After` for route and global throttle rules on routed and unrouted paths, and passes itself to the behavioral processor so `correlate_with_detection` sees the detection hits. guard-core 5.0.0 also enforces the rules in its own pipeline and each request records its hit once, so the adapter's call and the engine's never count a request twice. If your clients began to receive `429` after the upgrade, a throttle rule you configured is now doing what it says: raise its threshold or window.

- **Changed (behavior)** - **`security_headers` settings are applied by guard-core's `apply_security_headers_settings`, and the startup call of the global manager no longer overrides other apps.** The adapter's own reader is gone: a partial block merges over the engine defaults (a block that leaves `xss_protection` out sends `X-XSS-Protection: 0`, where the adapter's reader sent `1; mode=block`), and `hsts: None` configures the manager instead of raising. The middleware's own call to the global `security_headers_manager.configure(...)` passes `override_apps=False`, so it fills the manager's own state as before and no longer sets the cross-app override to this app's config: two apps with different CSPs each keep their own. A call you make yourself with `override_apps=True` still reaches every guarded app, and one without it reaches none.

- **Changed (behavior)** - **`Origin` is merged into the application's `Vary`, and the strict-mode `405` carries `Allow`.** The CORS pass replaced the response's `Vary` with the engine's, dropping a `Vary` the view had set (`Accept-Encoding`, for one). It now merges `Origin` into the existing header and keeps a value that already lists `Origin` or `*` as it is. With `route_resolution_strict` the `405` for a wrong method carries `Allow` (RFC 9110 section 15.5.6), built from the Werkzeug URL map.

- **Changed (behavior)** - **`passive_mode` admits a request when Redis is down at initialization.** A `GuardRedisError` from the first initialization answered `503`. Under `passive_mode` it now passes the request through unguarded with a sampled log line. Without `passive_mode` the answer stays `503` with `Retry-After`.

- **Fixed** - **A ban made inside a view goes through its own app.** The adapter holds the app's scope across the view and releases it in `teardown_request`, so a ban, an event or a Redis write made from a handler of one app goes through that app's own handlers, trusted proxies and Redis prefix when two apps share a process.

- **Fixed** - **`agent_stats` answers with the agent on.** Once the engine swapped in its `CompositeAgentHandler`, `agent_stats` raised `AttributeError` because the composite had no `get_stats`. The adapter now calls `get_stats` on the handler without a cast, and guard-core returns the stats of the handlers that have one.

- **Added** - **The response wrapper declares `body_is_materialized`.** The wrapper reports `not is_streamed`, read before anything touches `.data` or `get_data()`, so the engine hands a body-reading `custom_response_modifier` the real response for a buffered response and takes its bounded path for a streamed one. A streamed response is teed instead of buffered: a declared `Content-Length` within the cap is read to its end, any other stream stops at the first non-empty chunk, and every byte still reaches the client. A modifier that reads a refused body sees the engine's `ResponseBodyUnavailableError`.

- **Changed** - **The config is a `SecurityConfig[SyncGuardRequest]`, and the extension has no `cast` and no explicit `Any`.** guard-core 5.0.0's `SecurityConfig` is generic in the request type, and a WSGI adopter who runs `mypy` writes `SecurityConfig[SyncGuardRequest](...)` out (mypy does not always infer it from a sync check); a plain `SecurityConfig(...)` is the async form. The sync `custom_request_check` and `custom_response_modifier` are passed to the engine without a cast, `mypy` runs with `disallow_any_explicit` on `flaskapi_guard` behind a ratchet, and the request-headers and agent-handler guards are gone now that the engine and the agent are typed.

- **Added** - **Python 3.15 is supported.** `requires-python` is now `>=3.10,<3.16` and 3.15 joins the test matrix as a required version.

- **Fixed** - **An oversize body under `MAX_CONTENT_LENGTH` answers `413` again, without the suspicious-activity warning.** The adapter's body read let Werkzeug's `RequestEntityTooLarge` reach the engine, which reported an unreadable body: `400` and a warning for every oversize request. The adapter now leaves the body to Flask, so the view's own read answers `413` as in v4.4.0.

- **Fixed** - **A `bypass(["all"])` view runs inside its own app's scope.** The scope was held after the guard phase that calls the bypass view, so in a process with two guarded apps a ban, event or Redis write made by that view used another app's configuration. The scope is now held right after lazy initialization, before the bypass view runs.

- **Fixed** - **The first request initializes the handlers once.** Concurrent first requests each ran the lazy initialization and rebuilt the event bus, bypass handler and behavioral processor while others were served. The initialization now takes a lock, and the requests that waited for it find it done.

- **Fixed** - **Routes on a subdomain or under `host_matching` are visible to the route gate.** `resolve_route`, the static-file check and `allowed_methods` bound the URL map with no host, so such a route was not found: with `route_resolution_strict=True` a wrong-method request to it was answered `404` without `Allow`, where the unguarded app answers `405` with `Allow`. They now bind the URL map as Flask binds it for the request being served.

- **Fixed (docs)** - **The docs state how a dynamic rule combines with the config, and what `passive_mode` does for a client with no address.** A dynamic rule adds to your configuration and never wipes it: blocked countries, blocked cloud providers and blocked user agents are added to your static lists, `whitelist_countries` is replaced only when the rule's value is non-empty and valid, and `endpoint_rate_limits` merge per endpoint (the rule's value wins for the endpoints it names, your static limits stay for the rest). A request from a client with no address is refused under `fail_secure` (the default) and logged and admitted under `passive_mode`; the architecture pages that said it passes through are corrected.

- **Fixed** - **A response a custom hook returns without a `Content-Type` is served as `text/plain; charset=utf-8`.** `unwrap_response` handed the framework default type (`text/html`, or a sniffed one) to a foreign `GuardResponse` that named none, so a `custom_request_check` response that echoes request text was a reflected XSS. The unwrapped response now carries `text/plain; charset=utf-8` when no header named `Content-Type` in any case is present; a `Content-Type` the hook sets, in any case, is kept as it is. Behavior change for a hook that returned HTML or JSON without naming the type: it now has to set `Content-Type` itself.

___

v4.4.0 (2026-10-15)
-------------------

Engine routing parity with fastapi-guard (v4.4.0)
-------------------------------------------------

- **Changed** - Passthrough, the route all-checks bypass and the response pass now go through the guard-core engine like fastapi-guard (#40, closes #39). Passthrough uses the engine `BypassHandler.handle_passthrough`, and `@security.bypass_all()` routes use `handle_security_bypass`, which calls the real view and applies the response modifier. Excluded paths stay scoped: the checks that apply to them still run instead of being skipped.
- **Changed (behavior)** - A request with no client address is now answered with `403` under the default `fail_secure=True`. It used to skip the security pipeline and reach the view. If you depend on the old pass-through, set `fail_secure=False` in `SecurityConfig`.
- **Fixed** - Blocked, preflight and bypass responses no longer emit request metrics and no longer get the pass-through response pass. `_after_request` runs the engine response pass only for responses that came out of the view.
- **Fixed** - Global behavioral return rules (`global_behavior_rules`) are now passed to the engine response pass, so they run.
- **Added (tests)** - `tests/test_engine_parity.py` drives the extension with the Flask test client against the real engine handlers. The test that asserted the old no-client-address pass-through now asserts the `403`.
- **Compatibility** - The `guard-core` floor rises from `>=4.1.0` to `>=4.4.0`, so upgrading flaskapi-guard also brings the guard-core 4.4.0 detection and dynamic rule fixes (Cookie header scanned per pair, the per-request scan budget, the semantic-only header opt-out and dynamic rule versions applied over the base config). No public API of this adapter changed.
- **Chore** - The sponsor button points at the maintainer's Sponsors page, the mkdocs `site_url` drops `/latest/` so canonical URLs resolve, the README markdown lint errors that blocked the docs deploy are fixed and the README was brought to content parity (#32, #35, #37, #38), a CODEOWNERS file was added and the family Discord relay workflow was added (#31, #33).

___

v4.3.3 (2026-10-08)
-------------------

Guard-Core org migration
------------------------

Metadata release: PyPI project URLs, the docs canonical domain, and all repository links moved to the Guard-Core org. No code changes.

___

v4.3.2 (2026-09-26)
-------------------

Block response Content-Type, guard-core 4.1.0 tracking (v4.3.2)
---------------------------------------------------------------

- **Fixed** - Blocked responses now declare `Content-Type: text/plain` (#25): the Flask response factory left Flask's default mimetype in place, so middleware-generated 403/429/400 pages went out without an explicit content type and clients were left guessing. The factory now passes `mimetype="text/plain"`, matching the engine's reference response factory and the fastapi-guard fix (#144).
- **Compatibility** - The `guard-core` floor moves from `>=4.0.0` to `>=4.1.0` in `pyproject.toml` (no upper bound), so this adapter tracks the guard-core 4.1.0 engine (the exempt_ips skip-list, the recon leading-separator gate, the raw-view recon scan, the cross-engine interop harness). The adapter delegates all security behavior to the engine through the unasync-generated sync mirror; no sync API flaskapi-guard uses changed shape.

___

v4.3.1 (2026-09-23)
-------------------

guard-core 4.0.x tracking: dependency floor to >=4.0.0, agent docs (v4.3.1)
---------------------------------------------------------------------------

- **Compatibility** - The `guard-core` floor moves from `>=3.15.0` to `>=4.0.0` in `pyproject.toml` (no upper bound), so this adapter tracks the guard-core 4.0.x engine line and is verified against guard-core 4.0.4. No adapter code changed: the delta since 4.3.0 is docs and CI only, hence the patch bump. Since the adapter delegates all security behavior to the engine, no other change is required for the 4.0.x line; guard-core 4.0.0's own breaking changes (grammar-based secret redaction, exact-value `require_headers()` enforcement, `excluded_detection_headers` semantics) are documented in the guard-core changelog.
- **Documentation** - Added `AGENTS.md`/`CLAUDE.md` agent guidance and the flaskapi-guard package skill, and noted in the access-control decorator docs that an unknown bypass token now warns.

___

v4.3.0 (2026-08-31)
-------------------

guard-core 3.15.0 lockstep: lazy Redis initialization, unknown-identity access change (v4.3.0)
------------------------------------------------------------------------------------------------

- **Fixed** - `FlaskAPIGuard.init_app()` called `_initialize_handlers()` eagerly at construction, so an unreachable Redis raised `GuardRedisError` straight out of `FlaskAPIGuard(app, config=...)` and the app object never finished constructing; recovering needed a process restart. Initialization is now lazy, running at the top of `_before_request()` guarded by an `_initialized` flag: a `GuardRedisError` raised there is caught and logged, and the request returns `503` with a `Retry-After: 5` header instead of crashing the app, leaving the flag unset so the next request retries. `redis_fail_open` and `fail_secure` semantics are unchanged; guard-core still owns that policy (guard-core #76).
- **Fixed (tests)** - `test_request_without_client` asserted the pre-3.14.0 behavior (403) for a request that resolves to the "unknown" client identity. guard-core 3.14.0 changed `check_ip_access` to treat "unknown" as no address available and allow the request unless `whitelist` or `whitelist_countries` is configured, since the blacklist, `blocked_countries`, and cloud-provider checks cannot match without an address (GHSA-634g-4wr8-xwxv); the test now asserts `200`, and a new `test_request_without_client_unknown_identity_with_whitelist_is_blocked` covers the other half of the rule: an unknown identity is still blocked when a whitelist is configured. `test_rate_limiter_redis_errors` asserted the old silent in-memory fallback on a Redis failure; guard-core's rate limiter now honors `redis_fail_open` like every other check and raises `GuardRedisError` when it is `False` (the default), so the test now asserts the raise and adds a `redis_fail_open=True` case for the fallback. Tests that inspected state built by `_initialize_handlers()` (composite agent handler wiring, behavior tracker threading, the rate limiter's Redis handler, Lua script loading, Redis handler call assertions) now call the extension's `_ensure_initialized()` explicitly, since that state no longer exists immediately after construction; `test_redis_initialization` and `test_redis_initialization_without_ipinfo_and_cloud` keep their existing `lazy_init=False` (guard-core 3.13.0's daemon-thread race) alongside the explicit call.
- **Added (tests)** - `test_redis_unavailable_at_first_request_returns_503_and_retries` covers the new lazy-init path end to end: a first request with Redis unreachable gets `503` with `Retry-After: 5` and leaves the extension uninitialized, and a second request against a reachable Redis succeeds and completes initialization.
- **Compatibility** - Requires guard-core 3.15.0 (`guard-core>=3.15.0`, previously unconstrained). No public API of this adapter changed. Lockstep with fastapi-guard 7.8.2 on the guard-core 3.15.0 line.

___

v4.2.0 (2026-08-25)
-------------------

guard-core 3.13.0 compatibility: inline bypass replication, bounded body readers, behavior-scan and auth-verifier lockstep (v4.2.0)
----------------------------------------------------------------------------------------------------------------------------------

- **Fixed** - guard-core 3.12.0 (commit 30f43944) made `BypassHandler.handle_passthrough` and `handle_security_bypass` require a `call_next` callable, so this adapter's calls without it raised `TypeError` on every request and cascaded to HTTP 500. Flask's `before_request` hook cannot invoke the downstream view, so unlike the Django and Starlette adapters it cannot supply a real `call_next`; `_check_passthrough` and `_check_security_bypass` now replicate the bypass decision inline instead of calling `handle_passthrough` / `handle_security_bypass`. A falsy `client_host` (no-client passthrough) or a non-passive `@security.bypass_all()` route sets `flask.g.guard_passthrough`, and `_before_request` skips the security pipeline when that flag is set, letting the view run and `_after_request` apply the response modifier through `process_response`. The `security_bypass` event is emitted with the same arguments guard-core uses, and the no-client-host passthrough short-circuits before the bypass check, matching fastapi-guard.
- **Added** - `FlaskGuardRequest.read_body_prefix(max_bytes)` and `FlaskGuardResponse.read_body_prefix(max_bytes)` implement guard-core 3.12.0's `SyncBoundedBodyReader` / `SyncBoundedResponseBodyReader` protocols, so response-body `return_pattern` rules (`json:`, `regex:`, bare substring) and bounded request-body inspection actually match for the first time in this adapter.
- **Fixed (tests)** - The behavioral decorator fixture now sets `behavior_scan_response_body=True` before applying `return_monitor` / `behavior_analysis` decorators, since guard-core 3.12.0 rejects body-reading `return_pattern` rules at decorator-apply time when that flag is off. The auth fixture supplies an `auth_verifier` callable, since guard-core 3.13.0 fail-closes `require_auth` / `api_key_auth` with HTTP 401 when no verifier is resolvable. The stale `mock.patch` of `guard_core.sync.core.checks.implementations.suspicious_activity.detect_penetration_patterns` (removed in guard-core 3.12.0's detection-cache seam) is replaced with a patch of `guard_core.sync.core.checks.helpers.detect_penetration_attempt`. The honeypot tests feed `read_body_prefix` on their mocked request because guard-core 3.12.0's body reader calls it when no `content-length` header is present. The `test_before_request_passthrough_response` and `test_before_request_bypass_response` tests were rewritten to exercise the inline replication directly instead of mocking the now-removed bypass-handler calls, and `test_before_request_bypass_passive_mode` covers the passive-mode branch. Seventy-two pre-existing mypy errors across the test suite (list literals passed to `SecurityConfig` fields that are now `tuple` / `frozenset`) are fixed.
- **Compatibility** - Requires guard-core 3.13.0. No public API of this adapter changed: `FlaskAPIGuard`, `FlaskGuardRequest`, `FlaskGuardResponse` and the re-exported decorators keep their signatures; the new `read_body_prefix` methods are additive. Lockstep with djangoapi-guard and fastapi-guard 7.7.0 on the guard-core 3.13.0 line.

___

v4.1.0 (2026-07-29)
-------------------

Unmatched requests are reported to guard-core (v4.1.0)
-------------------------------------------------------

- **Added** - `_populate_guard_state()` returned silently when Flask matched no rule, which is indistinguishable from a view that simply carries no decorators. guard-core reads both as "nothing to enforce", so a resolution failure silently skips every per-route check - the fail-open half of [GHSA-f2vm-w8gq-h378](https://github.com/rennf93/fastapi-guard/security/advisories/GHSA-f2vm-w8gq-h378), reported against the Starlette adapter. Flask routes requests itself, so this adapter has no equivalent matching bug, but it now reports the failure by setting `request.state.guard_route_unresolved` when `request.endpoint` is unset or its view function is missing. A matched view without `_guard_route_id` is left alone, since an undecorated view legitimately has no per-route config. With guard-core >= 3.7.0 and `SecurityConfig.route_resolution_strict=True`, unmatched requests are logged, emit a `route_unresolved` event, and are blocked with `500`. Behaviour is unchanged by default and on older guard-core, which ignores the attribute.
- **Fixed (tests)** - The IPv6 and mixed IPv4/IPv6 allow-list tests still encoded pre-3.2.0 guard-core semantics, where the blacklist was evaluated before the whitelist. Since guard-core 3.2.0 an explicit whitelist match overrides the blacklist, so an address inside both a whitelist CIDR and a blacklist entry is now served rather than blocked. `test_multiple_decorators` likewise predated guard-core 3.5.0, where a route `@require_ip` match grants the IP aspect only, so a route-blocked country still denies the request. CI floats guard-core to the latest release and had not run here since 2026-05-28, so these only surfaced now; the adapter itself was correct throughout.
- **Fixed (CI)** - The greetings workflow passed `issue-message`/`pr-message` to `actions/first-interaction@v3`, which expects `issue_message`/`pr_message`, so the job failed on every first-time issue and pull request.

___

v4.0.1 (2026-05-27)
-------------------

guard-core 3.1.0 compatibility + PEP 639 license metadata (v4.0.1)
------------------------------------------------------------------

- **Fixed** - guard-core 3.1.0 narrowed `block_cloud_providers` to `set[Literal["AWS", "GCP", "Azure"]]`; `refresh_cloud_ip_ranges()` now normalizes it to `set[str]` before calling `cloud_handler.refresh_async`, resolving a `set`-invariance mypy error. Runtime behavior is unchanged.
- **Packaging** - Migrated license metadata to PEP 639: `license = "MIT"` (SPDX expression) plus `license-files = ["LICENSE"]`, and dropped the deprecated MIT license classifier.
- **Build** - Removed the unused `setup.py`; the release workflow now builds via `python -m build` (hatchling backend) instead of `python setup.py sdist bdist_wheel`.

___

v4.0.0 (2026-04-29)
-------------------

Fail-secure by default (upstream), agent-stats surface, version reporting (v4.0.0)
----------------------------------------------------------------------------------

- **Breaking (upstream)** - `SecurityConfig.fail_secure` now defaults to `True` (inherited from `guard-core >= 3.0.0`). When any security check raises an unhandled exception, the request is now blocked with HTTP 500 instead of logging and falling through. Bugs in checks that previously slipped past as silent fail-open responses now surface immediately. Restore the old behavior on deployments that depend on it via `SecurityConfig(fail_secure=False)`. Recommended migration: keep the new default, surface any check exceptions in your monitoring, and fix them - the previous default could mask serious bugs. The flaskapi-guard major bump tracks this upstream change so deployments see a clear signal.
- **Added** - `FlaskAPIGuard.agent_stats` read-only `@property` returning the agent's telemetry buffer state. Returns `{"enabled": False}` when no agent is wired; otherwise returns `{"enabled": True, **agent_handler.get_stats()}` exposing `events_dropped`, `metrics_dropped`, `circuit_breaker_state`, and other agent counters. No caching - fresh on each call. Access the property on the extension instance returned by `FlaskAPIGuard(app, config=...)` or via `app.extensions["flaskapi_guard"]["guard"].agent_stats`. Lets app teams build Flask health endpoints that surface agent-side drops and circuit-breaker trips without scraping the agent directly.
- **Added** - `from flaskapi_guard import __version__` - package version is now exported via `importlib.metadata.version("flaskapi_guard")` with a `"0.0.0+unknown"` fallback if the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` so application code can wire the flaskapi-guard version through to the agent for SaaS-side telemetry attribution: `SecurityConfig(agent_guard_version=__version__)`.
- **Fixed (latent)** - `FlaskAPIGuard.refresh_cloud_ip_ranges` was calling `cloud_handler.refresh(...)` directly. When Redis was enabled, that method raises `RuntimeError("Use refresh_async() when Redis is enabled")` - the cloud-IP refresh check would surface as an exception inside the security pipeline. Under the old `fail_secure=False` default the exception was logged and the request fell through, so the bug stayed invisible. Under the new `fail_secure=True` default it would block every request with HTTP 500 in any deployment that combines `enable_redis=True` with `block_cloud_providers`. Switched to `cloud_handler.refresh_async(...)` which dispatches Redis-aware vs non-Redis paths internally (matches djangoapi-guard's v3.0.0 fix and tornadoapi-guard's existing dispatch). Same fix shape; pre-existing bug.
- **Compatibility** - `FlaskAPIGuard.agent_stats` is purely additive; no existing API was changed. `__version__` was previously absent; reading it before this release returned `None` via missing-attribute fallback in some integrations.

___

v3.0.0 (2026-04-26)
-------------------

Pipeline-first CORS via guard_core.cors_handler (v3.0.0)
--------------------------------------------------------

- **Breaking** - Preflight `OPTIONS` requests are now subject to the security pipeline (previously short-circuited inside the extension). Banned IPs and rate-limited clients can no longer preflight freely.
- **Breaking** - CORS is now configured exclusively via `SecurityConfig.cors_*` fields. The extension wires `_before_request` / `_after_request` automatically; no separate `configure_cors` entry point.
- **Fixed** - Cross-origin preflight requests to passthrough paths (e.g. `exclude_paths=["/health"]`) now receive a valid CORS response. Preflight handling runs ahead of the passthrough/bypass short-circuit so the browser permission check works for excluded paths.
- **Fixed** - Cross-origin GETs to passthrough/bypass paths now carry CORS headers on their responses, matching the previous outer-CORSMiddleware semantics.
- **Internal** - Both lifecycle hooks delegate to the new shared `guard_core.sync.handlers.cors_handler.CorsHandler`. Removed all `[[tool.mypy.overrides]] ignore_missing_imports = true` / `follow_imports = "skip"` blocks; replaced with proper inline-typed packages and `django-stubs`. Stripped `[tool.uv.sources] guard-core` local-path block from committed pyproject.toml. Added `guard-agent` to dev dependencies (was previously declared only in deptry's per-rule-ignores).
- **Requires** - `guard-core>=2.2.0`.

___

v2.2.0 (2026-04-25)
-------------------

guard-core 2.0.0 protocol-shape adjustment (v2.2.0)
---------------------------------------------------

- **Requires** - guard-core 2.0.0 or newer. guard-core's major bump migrates `suspicious_request_counts` to a per-category nested dict, replaces `detect_penetration_attempt` / `detect_penetration_patterns` 2-tuple returns with `DetectionResult`, and migrates the cloud-IP cache namespace.
- **Updated** - `FlaskAPIGuard.suspicious_request_counts` is now typed `dict[str, dict[str, int]]` to match guard-core's per-category counter shape.
- **User-visible impact** - User code that didn't reach into those internals continues to work unchanged.

___

v2.1.1 (2026-04-25)
-------------------

Integration fixes for OTel + enrichment pipeline (v2.1.1)
---------------------------------------------------------

- **Fixed** - After composite construction, `self.agent_handler` is rebound from the bare `guard-agent` client to the composite. Downstream callers that receive `extension.agent_handler` (most notably `guard_core.utils.extract_client_ip → send_agent_event`) now route through the composite, so enrichment and OTel see every event.
- **Fixed** - `BehavioralContext` now receives `handler_initializer.behavior_tracker`, matching the guard-core 1.2.1 wiring. This closes the architectural gap so `guard.behavior.recent_event_count` populates end-to-end when `enable_enrichment=True`.
- **Added** - `tests/test_extension_lifecycle.py` - regression tests pinning the agent_handler rebind and behavior_tracker threading.
- **Requires** - `guard-core>=1.2.1` for the matching OTLP endpoint normalization and `BehaviorTracker` wiring fixes. Install the latest with `uv add flaskapi-guard guard-core` or `pip install -U flaskapi-guard guard-core`.
- **User-visible impact** - Users with `enable_otel=True`, `enable_logfire=True`, or `enable_enrichment=True` previously saw silent drops on a portion of events because callers using `extension.agent_handler` directly bypassed the composite handler. After this release every downstream caller routes through the composite, so all events flow through telemetry and enrichment as configured.

___

v2.1.0 (2026-04-24)
-------------------

Telemetry pipeline wiring fix (v2.1.0)
--------------------------------------

Adopts guard-core 1.1.0 and fixes an extension wiring bug that prevented OpenTelemetry, Logfire, and event/metric/check-log muting from seeing anything emitted by the request-path security pipeline.

- **Fixed** - `FlaskAPIGuard.init_app()` previously constructed `SecurityEventBus(agent_handler, ...)` and `MetricsCollector(agent_handler, ...)` in `_init_core_components()` using the bare `guard_agent` handler (or `None`). `_initialize_handlers()` then called `HandlerInitializer.initialize_agent_integrations()` which built a `CompositeAgentHandler` that no code path ever reached, because the event bus / metrics collector were already frozen on the bare handler. As a result, every event emitted through the request pipeline (`SecurityEventBus.send_middleware_event`) and every request metric bypassed OTel, Logfire, and the configured `muted_event_types` / `muted_metric_types` filter. This release splits construction into `_init_core_components()` (handler_initializer only), `_init_route_resolver()`, and `_build_event_bus_and_contexts()` - the last of which consults `handler_initializer.composite_handler` and uses `build_event_bus()` / `build_metrics_collector()` when the composite is available. `_initialize_handlers()` now re-invokes `_build_event_bus_and_contexts()` after `initialize_agent_integrations()` so the dependent contexts (`ResponseContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`) bind to the post-init event bus.
- **Added** - `tests/test_extension/test_extension_wiring.py` - four regression tests that pin `ext.event_bus.agent_handler` and `ext.metrics_collector.agent_handler` to `CompositeAgentHandler` after `init_app` when OTel or Logfire is enabled, and confirm all dependent contexts reference the post-init event bus.
- **Dependencies** - `guard-core>=1.1.0,<2.0.0`.
- **User-visible impact** - Users already setting `enable_otel=True` or `enable_logfire=True` on `SecurityConfig` were previously getting handler-path events only (ip_banned, rate_limited from `ip_ban_manager` / `rate_limit_handler`, etc.) - but never pipeline-path events (`penetration_attempt`, `authentication_failed`, `user_agent_blocked`, `https_enforced`, etc.) or request metrics (`guard.request.duration`, `guard.request.count`, `guard.error.count`). After this release, every event and every metric flows through the composite, which means OTel spans, Logfire logs, and all mute fields (`muted_event_types`, `muted_metric_types`, `muted_check_logs`) work as documented. No `SecurityConfig` changes required; existing configurations produce strictly more telemetry, not less.
- **Tests** - `tests/test_extension/test_security_extension.py::test_request_without_client` updated: when `extract_client_ip` returns `"unknown"`, `is_ip_allowed` raises `ValueError` on the unparseable IP and the `ip_security` check correctly returns 403. The test now pins that deterministic-403 contract rather than the stale pre-1.1.0 200.

___

v2.0.0 (2026-03-26)
-------------------

Major Release (v2.0.0)
------------

- **Guard-Core migration**: FlaskAPI Guard is now a thin adapter over [guard-core](https://github.com/rennf93/guard-core), the framework-agnostic security engine. All security logic (17 checks, 8 handlers, detection engine) lives in guard-core; this package provides only the Flask integration layer.
- **Production/Stable status**: Development status upgraded from Alpha to Production/Stable.
- **Zero breaking changes to public API**: All existing imports (`from flaskapi_guard import SecurityConfig`, `from flaskapi_guard import FlaskAPIGuard`, etc.) continue to work exactly as before.
- **Shared engine across frameworks**: The same security engine now powers [fastapi-guard](https://github.com/rennf93/fastapi-guard) and [djangoapi-guard](https://github.com/rennf93/djangoapi-guard), ensuring consistent security behavior across all three frameworks.

___

v1.1.1 (2026-03-16)
-------------------

Bug Fixes (v1.1.1)
------------

- **Per-endpoint rate limit check**: Fixed rate limit check to properly evaluate endpoint-specific rate limits. Previously, the rate limit check was only evaluating global rate limits.

___

v1.1.0 (2026-03-14)
-------------------

New Features (v1.1.0)
------------

- **Configurable cloud IP refresh interval**: New `cloud_ip_refresh_interval` config field (default: 3600s, valid range: 60-86400s) allows tuning how often cloud provider IP ranges are refreshed. The interval is propagated to Redis TTL for cache consistency.
- **Change detection logging for cloud IP refreshes**: When cloud IP ranges are refreshed, additions and removals are logged per provider (e.g., `+12 added, -3 removed`), providing visibility into IP range mutations.
- **Context-aware detection engine**: Suspicious pattern rules are now tagged with applicable input contexts (`query_param`, `url_path`, `header`, `request_body`). Patterns are only evaluated against relevant input sources, reducing false positives.
- **Structured JSON logging**: New `log_format="json"` config option outputs logs as structured JSON (`{"timestamp": "...", "level": "...", "logger": "...", "message": "..."}`), enabling integration with log aggregation systems (ELK, Datadog, CloudWatch).
- **Per-provider `last_updated` timestamps**: `CloudManager` now tracks when each provider's IP ranges were last refreshed via `cloud_handler.last_updated["AWS"]`, returning `datetime | None`.

___

v1.0.0 (2026-03-13)
-------------------

Initial Release (v1.0.0)
------------

- Initial release of Flask API Guard
- IP whitelisting/blacklisting with CIDR support
- Rate limiting (global and per-endpoint)
- Automatic IP banning
- Penetration attempt detection
- User agent filtering
- Content type filtering
- Request size limiting
- Time-based access control
- Behavioral analysis and monitoring
- Custom authentication schemes
- Honeypot detection
- Redis integration for distributed environments
- Security headers management
- CORS configuration
- Emergency mode

___
