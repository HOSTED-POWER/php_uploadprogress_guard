# hp_uploadprogress_guard

**v3.2.4, 23 October 2026: two protections PHP itself does not ship yet.** Since the php2shell releases, two
more problems have surfaced in current PHP. This module now covers both, on patched and unpatched PHP alike,
so **keep it installed after you upgrade.**

* **`unserialize()` use-after-free, in every current release.** When `unserialize()` cleans up, it frees its
  bookkeeping first and then runs object destructors; a destructor that calls `unserialize()` again works on
  freed memory. This is the bug behind the "PHP 8.5.12 patch is incomplete" claims. Present in 8.5.12,
  8.4.27, 8.3.36, 8.2.35 and older; reachable when an application unserializes attacker-controlled data, or
  by code already running on the host. Not fixed in any PHP release, no CVE (PHP does not assign CVEs to
  `unserialize()` bugs): [php-src#24481](https://github.com/php/php-src/issues/24481).
  **Closed by the module since v3.2.0**: such nested calls get their own state. Verified with Valgrind on all
  five releases named here: freed-memory reads without the module, none with it.
* **SimpleXML crashes, introduced by 8.4.27 and 8.5.12.** The security release changed the garbage collector,
  and SimpleXML now frees its property table twice when an object converted with `json_encode()`, `(array)`
  or `get_object_vars()` (the everyday `json_decode(json_encode($xml), true)`) is collected in a reference
  cycle: `zend_mm_heap corrupted`, a crashed worker. Fix approved by PHP, not released yet:
  [php-src#24488](https://github.com/php/php-src/issues/24488).
  **Fixed by the module since v3.2.1**, by applying PHP's approved fix from inside the module, only on those
  two releases. On a staging host with 8.4.27, a plain SimpleXML script crashed before and completed after.

Nothing changes for applications: identical output with and without the module on every branch from 5.4 to
8.5, and PHP's own serialize, session and SimpleXML test suites give the same results. Details and tests
further down.

**What it is.** A small PHP extension that mirrors the official fix for
CVE-2026-109618 / CVE-2026-109619 component by component, so that on an unpatched PHP every link of
the published attack chain is removed, without rebuilding PHP and without changing anything for the
applications on the host. Built by [Hosted Power](https://www.hosted-power.com) for its own fleet,
published for everyone. PHP 5.4 through 8.5; Sury, Remi, cPanel EA4, DirectAdmin CustomBuild, official
Docker images. **Prebuilt for Linux x86_64 and arm64 (aarch64), every branch from 5.4 to 8.5, and for
Windows x64** (7.2 to 8.5, nts and ts), with checksums; one C source file for everything else. On a PHP that already carries the php2shell fix,
vendor backports included, its php2shell layers notice that and step aside; the two protections above stay on,
and so does the detached session upload-progress handler (see point 4 below).

**Install the official PHP release** (8.5.12, 8.4.27, 8.3.36, 8.2.35, and the PHP team's backports
for 7.4, 8.0 and 8.1, which Sury extended down to 5.6); we recommend it without reservation. **This
module protects an unpatched PHP for real.** It mirrors the official fix component by component,
tested per branch and per SAPI (see the tests below), so a host that runs it is protected today,
whether its packages arrive tomorrow or never. After the upgrade its php2shell layers step aside on their
own, so there is nothing to undo, and the v3.2.0 `unserialize()` protection keeps running. Read the advisories:
[GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

What the advisories say, in one paragraph. CVE-2026-109619: the session upload-progress handler runs
on every multipart request before the request is initialised and can consume state a previous request
on the same worker left behind; PHP's own mitigation is `session.upload_progress.enabled=0`. Validated
RCE on mod_php and php-fpm. CVE-2026-109618: if PHP runs out of memory while the request is still
being set up, the engine `longjmp`s out and request shutdown runs on half-initialised state; the
advisory lists three multipart ways to get there (a body without a usable Content-Length, a flood of
part headers, a flood of empty file controls that each still produce `$_FILES` arrays). Validated RCE
on mod_php, where shutdown runs after a failed startup. v3.0.0 removes the handler, carries the fixed
parser, and makes it impossible for the parser to run out of memory in the first place.

**v3.0.0 also fixes v2.2.0 on PHP 7.0 to 7.4**, where the carried parser rejected every multipart
request (`Multipart body parts limit exceeded 0`) because it read an ini setting that only exists from
8.0.28. If you installed v2.2.0 on a 7.x host, update.

**v3.0.1** (same day): the v3.0.0 binaries for 8.2 to 8.5 were built on Debian 13 and required
`GLIBC_2.38`, so they did not load on Debian 12 or older (`PHP Startup: Unable to load dynamic library`;
PHP kept running without the guard). Every binary is now built on the oldest Debian that ships the
minor and `build.sh` refuses anything above `GLIBC_2.14`. Also in v3.0.1: requests on hosts with
`mbstring.encoding_translation=On` are handed to PHP's own parser (mbstring's multibyte hooks are
file-static and cannot be mirrored; the callback detach still applies), the 8.0 to 8.3 copies no longer
depend on `max_multipart_body_parts` existing (it was added mid-branch, so a stale 8.0.x/8.1.x/8.2.0-2
install hit the 7.x failure), the parser copies no longer export PHP's own symbol names, `mode` is
case-insensitive, any PHP newer than 8.6 counts as patched, and `cd src && phpize && ./configure && make`
works again (config.m4 picks the parser copy for the PHP it is built against).

**v3.0.2** (same day): `session.upload_progress.enabled` now reads as Off. The handler detach already
made the setting meaningless, but `ini_get()` and `phpinfo()` kept reporting `On`, which confused
scanners and customers. The module now writes the master value to `0` at startup and locks the entry at
`PHP_INI_SYSTEM`, so `ini_get()` returns `"0"`, `phpinfo()` shows `Off => Off`, and `.user.ini`,
`.htaccess` or `ini_set()` cannot change it. No other behaviour changed; binaries rebuilt for 5.6 to 8.5
with the same glibc floor.

**v3.1.0** (same day, evening): the rest of the official fix, mirrored. v3.0 covered the multipart
parser; v3.1 covers what the patch does outside it. Nothing changes for applications: uploads, forms, error handlers and warnings behave as
before. In detail:

* **Out-of-memory exit.** If memory still runs out while no script is executing (request startup or
  shutdown: PHP's own parser in `native` mode or the `mbstring.encoding_translation` case, a genuine
  out-of-memory from the operating system), the process ends with `_exit(137)` after unlinking the
  upload temp files it registered, instead of staying alive with half-cleaned state. That is what the
  official hard memory limit does, and what the PHP team chose for every memory exhaustion in the
  backports. php-fpm already discards a worker whose request startup failed; this matters for mod_php,
  LiteSpeed, FrankenPHP and any other SAPI that keeps the process.
* **Request state cleared at request end.** The patch writes safe values over a set of pointers the
  engine leaves behind at shutdown (user error and exception handlers, recorded errors, the object
  store, the superglobals, the `request_info` strings, on 8.5 the saved fatal-error backtrace), so that
  a warning raised before the next request's executor starts (an invalid `php_value` in `.htaccess`,
  a `PHP_VALUE` from the web server) finds nothing stale. The module writes the same values, a few
  steps later, in its post-deactivate function and in a wrapper around the SAPI's deactivate callback.
* **OPcache's compile window cannot run out of memory** (8.1 and later). The one part of the patch
  without a module equivalent is OPcache's deferred publication of class-cache slots in shared memory,
  which guards against a bailout while OPcache stores a freshly compiled script. The module keeps that
  window from bailing out instead: `memory_limit` is lifted while OPcache compiles and stores a script
  and restored right after, and the lift is visible in `--ri`.
* **Fix detection by symbol, not by version number.** Engines that carry the fix export a symbol the
  old ones lack (`zend_handle_delayed_oom` on 8.2 and later, `zend_mm_safe_error_ex` in the backports).
  The module checks for them through weak references (no `dlsym`, no glibc dependency), so vendor
  backports that keep their version number are recognised too. Verified on Sury's packages of
  21 October for 5.6, 7.0, 7.3, 7.4, 8.1 and 8.3: the module reports the fix and steps aside. Sury ships
  fixed packages for every branch from 5.6 to 8.5.
* **`hp_uploadprogress_guard.force_unlimited_memory = 1`**, opt-in: the advisories' `memory_limit=-1`
  mitigation, written as master value and locked at `PHP_INI_SYSTEM`. No memory-limit bailout can
  then start anywhere; bound the process with the operating system instead (cgroup `MemoryMax`).
  php-fpm pool directives for `memory_limit` are applied after the module starts and take precedence;
  `phpinfo()` and `--ri` show the effective value when that happens.
* Also: on 5.6 and 7.0, where a timeout can interrupt request startup, it is treated like memory
  exhaustion; `--ri` reports every mechanism and its state; binaries rebuilt for 5.6 to 8.5 with the
  same glibc floor, zero compiler warnings.

Build fixes, same evening (source only, binaries unchanged): the 7.4 and 8.0 parser copies build on
patch releases older than 7.4.14 / 8.0.1 again (#6), and `config.m4` picks the 5.6 parser copy for
PHP 5.4 and 5.5 (#5).

**22 October: on the follow-up reports in the press.** Two further PHP bug reports circulated on 21 and
22 October. One is the `unserialize()` use-after-free described at the top: it is real, it is present in
8.5.12, and v3.2.0 closes it. The other is a double free demonstrated with the Zend memory manager switched
off; the PHP team reviewed that responsibly disclosed report and stated it is "an unrelated issue with no
connection to the two vulnerabilities mitigated today" and "not urgent in any way". Neither touches the
multipart parser, session state, OPcache or the memory-limit bailout: the two critical vulnerabilities,
CVE-2026-109618 and CVE-2026-109619, are fixed in the released PHP versions and remain fully covered by this
module on unpatched engines.

**v3.2.0** (22 October): `unserialize()` re-entrancy isolation, details below.

* **The bug.** While an `unserialize()` call is active, a nested `unserialize()` or `session_decode()` shares
  its state (`BG(unserialize)`); PHP needs that for exactly one thing, a `Serializable::unserialize()` method
  the engine calls during parsing, whose own `unserialize()` must resolve the outer back-references. At the
  end of the outer call `var_destroy()` frees the back-reference chunks and then drops the deferred values
  (objects replaced by duplicate keys, the return value of `__wakeup()`, the argument of `__unserialize()`)
  without holding `serialize_lock`. A destructor that runs at that moment and calls `unserialize()` reads and
  writes the freed chunks.
* **The fix.** The module wraps `unserialize()` and `session_decode()`. A nested call keeps sharing state only
  when it comes from an engine-invoked `Serializable::unserialize()` with no destructor or generator in
  between; every other nested call runs exactly like a top-level call, with its own state, and the outer
  state is restored afterwards (also when the inner call ends in a fatal error). That is the behaviour the
  reporter proposes for PHP itself, applied from outside the engine, on every branch from 5.4 to 8.5.
* **What changes for applications.** Nothing on any normal path: top-level calls, `Serializable` nesting with
  shared back-references, `__wakeup()`/`__unserialize()` that unserialize, autoloaders, sessions, enums,
  fibers and generators behave exactly as before (identical output on all 14 branches, see the tests). Two
  cases change, both from broken to correct: a destructor that unserializes its own data with a
  back-reference during an outer call's cleanup got `false` or the wrong object from stock PHP, and gets the
  right result now; an exception it catches around such a call escaped as an uncaught fatal error on stock
  PHP, and is caught now.
* **Cost.** No measurable difference on normal calls; about 50 ns extra per nested call inside the
  deprecated `Serializable::unserialize()`.
* **Scope.** `unserialize()` and `session_decode()`. Extensions that unserialize with PHP's serializer
  internally (APCu, Memcached or Redis with the `php` serializer) are not wrapped; reaching the bug through
  them needs attacker-controlled cache contents and such a destructor. On PHP 5.x the reproducers take a
  different path and do not reach the bug; the isolation is active there too.
* **Switch.** `hp_uploadprogress_guard.unserialize_isolation = 1` (default; `PHP_INI_SYSTEM`). `php --ri
  hp_uploadprogress_guard` shows `unserialize() re-entrancy isolation ... => active (unserialize,
  session_decode)`. Unlike the php2shell layers it does not step aside on patched PHP, because no PHP release
  contains a fix.

**v3.2.1** (22 October): SimpleXML garbage-collector double free on 8.4.27 and 8.5.12.

* **The bug.** The fix for GH-24050 in 8.4.27 and 8.5.12 lets the garbage collector put the table an
  object's `get_gc` handler returns into its buffer. SimpleXML returns its own properties table there and
  frees it in `sxe_object_free_storage()` with `zend_hash_release()`, which leaves the buffer slot behind;
  the collector then frees the table a second time. Reached whenever a SimpleXML object whose properties
  were materialized (`json_encode()`, an `(array)` cast, `get_object_vars()`) is collected as part of a
  reference cycle. Reported as [php-src#24488](https://github.com/php/php-src/issues/24488) (Status:
  Verified); 8.4.26, 8.3.36 and 8.2.35 do not have it.
* **The fix.** The approved upstream fix releases the table with `zend_array_release()`, which removes it
  from the collector's buffer first. The module wraps SimpleXML's `free_obj` handler to do exactly that: it
  takes the table off the object, lets SimpleXML free the rest, and releases the table with
  `zend_array_release()`. Installed on the first request, only on 8.4 from 8.4.27 and 8.5 from 8.5.12; once
  PHP ships the fix the wrapper still releases the table exactly once, so it is harmless.
* **Switch.** `hp_uploadprogress_guard.simplexml_gc_fix = 1` (default; `PHP_INI_SYSTEM`). `php --ri
  hp_uploadprogress_guard` shows `SimpleXML GC double-free workaround (php-src#24488) => active` on the
  affected releases and `not needed (this PHP release)` elsewhere.

**v3.2.4** (23 October): status and documentation fixes reported in #17, #18 and #19, no change in what
is protected. phpinfo's `mbstring.encoding_translation requests` row now follows the setting instead of
only whether mbstring is loaded (#19). When an extension loaded before this one already cleared the session
upload-progress handler, `session.upload_progress.enabled` is now forced to `0` and locked as when the
module detaches it itself (#18). The README now states that the upload-progress detach stays on on patched
PHP, by design (#17).

**v3.2.3** (22 October, evening): thread-safe SAPIs ran PHP's parser, not ours. PHP keeps the table of
POST handlers in per-thread SAPI globals, and every new thread starts from PHP's default entries. The
module registered its multipart handler once, at startup, so on a thread-safe build with a threaded SAPI
(Apache `mod_php` with mpm_winnt, worker or event; the Windows `ts` DLLs are exactly that case) the request
threads kept PHP's own parser, `mode=block` could not refuse anything, and `--ri` still said "handler
replaced => yes" because that was a flag set at startup. Reported privately after #14 (thank you). Now the
handler is installed in every thread before its first request, and the status rows read the live table.
The other layers (upload-progress detach, out-of-memory exit, request-state reset, `unserialize()`
isolation) are process-wide hooks and were active on those threads all along. Not affected: NTS builds
(php-fpm, php-cgi, CLI, all prebuilt `.so` files and the `nts` DLLs) and prefork `mod_php`. Verified with
Apache mpm_event + a thread-safe PHP 8.4: before, concurrent uploads passed on every worker thread; after,
every one is refused in `mode=block`, and phpinfo on each thread reports the live state.

**v3.2.2** (22 October): PHP 5 thread-safe builds. The PHP 5 code paths used engine globals from functions
without a thread context, so a ZTS build of 5.4 to 5.6 (Linux `--enable-maintainer-zts`, Windows TS) did not
compile (#12, #13); the Windows symbol probe also named a PHP 7 function. Fixed: compiles, loads and passes
the behaviour suite on 5.4 and 5.6 ZTS (Linux), the multipart flood is handled on ZTS as on NTS. No change
in behaviour on NTS builds; the prebuilt files are rebuilt from the same source so they carry the version.

**22 October, later: Windows DLLs for PHP 5.6** (VC11, x64 and x86, nts and ts), built and load-tested in CI
against the official 5.6.40 VC11 builds; see [Windows](#windows).

**22 October: arm64 and Windows.** Prebuilt `.so` files for aarch64 (all branches 5.6 to 8.5, same old-glibc
images as x86_64) and Windows x64 DLLs for 7.2 to 8.5, nts and ts, built by the `Windows build` workflow with
the PHP team's php-windows-builder and loaded into a stock Windows PHP in the same run. The source needed
only portability changes (no behaviour change); x86_64 files are unchanged. See [Install](#install).

### What it does, silently

Three things happen at process start. None of them is visible to an application: uploads, forms,
`$_POST` and `$_FILES` behave exactly as before. The only feature that disappears is
`session.upload_progress`, which browsers replaced with native upload progress a long time ago.

1. **The session upload-progress handler is taken out of the multipart parser.** The advisory for
   CVE-2026-109619 names this handler as a confirmed way for stale request state to be consumed, and
   gives `session.upload_progress.enabled=0` as the official partial mitigation. The module does the
   same thing one level lower, by removing the handler from the parser's callback pointer, so no
   `.user.ini`, `.htaccess` or `ini_set()` can switch it back on.
2. **The multipart parser runs with the official hardening.** The module carries a copy of
   `main/rfc1867.c` from the patched releases, one per PHP branch (8.2 to 8.5 from the release tags,
   7.4/8.0/8.1 from the PHP team's backport branches, 7.0 to 7.3 and 5.6 with the same changes applied
   by hand). It keeps only the two part headers PHP uses and ignores duplicates, which removes the
   header memory-amplification path of CVE-2026-109618, and it enforces `post_max_size` on the bytes
   actually read, which closes the no-Content-Length bypass (on every branch since v3.0.0; v2.2.0 had
   it on 8.2 and later only). In this copy the callback of point 1 is compiled out entirely.
3. **The parser cannot run out of memory.** This is what v3.0.0 adds, and it is the part of the
   official fix a module could not carry as-is. The patched engine answers a memory-limit failure with
   a delayed, graceful out-of-memory at the next safe point instead of a `longjmp`; the carried parser
   uses the same checkpoints the PHP team put into `rfc1867.c` (every `ZEND_HAS_OOM()` and fallible
   allocation of the patch), but behind them it asks a different question: *would this step cross
   `memory_limit`?* It compares the allocator's own figure (`zend_memory_usage(1)`, the number the limit
   check uses) with the size the client is about to make it allocate, before every new part, every
   growth of a form-field value and every header line, and keeps an eighth of the limit (at least
   4 MB) plus one allocator chunk free for request startup and the script. If a step would not fit,
   parsing stops at that checkpoint with everything cleanly released, what was parsed is dropped,
   `$_POST` and `$_FILES` are empty, the response code is 413 and one line goes to the error log. The
   engine is never asked for memory it does not have, so the `longjmp` of CVE-2026-109618 cannot start
   inside the parser. A single part header is additionally capped at 64 KB. A request is only ever
   stopped when, without the module, it would have ended in `Allowed memory size exhausted`; the default
   `post_max_size=8M` against `memory_limit=128M` never comes near the line.
4. **It steps aside on a patched PHP.** At startup the module reads `PHP_VERSION` (8.5.12, 8.4.27,
   8.3.36, 8.2.35 or later) and, since v3.1.0, looks for the symbols only a fixed engine exports, which
   also recognises vendor backports that keep their version number. On such an engine it leaves PHP's
   own parser in place and switches its v3.1 mechanisms off. One deployment covers patched and
   unpatched hosts, and nothing has to be undone after the upgrade. **The upload-progress detach stays on
   by design:** the session upload-progress handler writes request data into the session from HTTP alone,
   the route the published attack used, and no PHP release needs it to be on. So on a patched engine too,
   `session.upload_progress.enabled` reads `0` and is locked. Hosts that rely on upload progress set
   `hp_uploadprogress_guard.detach_upload_progress = 0`. Since v3.2.4 the same holds when another
   extension loaded earlier already cleared the handler: the ini is forced to `0` and locked as well, and
   phpinfo says so.
5. **Nested `unserialize()` calls cannot reach freed memory** (since v3.2.0, on every engine, patched or
   not). A nested `unserialize()` or `session_decode()` from a destructor, a generator or anything else
   outside PHP's `Serializable` nesting runs with its own state, so it cannot work on the bookkeeping
   `var_destroy()` has already freed. See the v3.2.0 note above.
6. **SimpleXML does not crash the garbage collector on 8.4.27 and 8.5.12** (since v3.2.1). See the v3.2.1
   note above.

Since v3.0.2 the module also writes the master value of `session.upload_progress.enabled` to `0` and locks
the entry at `PHP_INI_SYSTEM`: `ini_get()` returns `"0"`, `phpinfo()` shows `Off => Off`, and `.user.ini`,
`.htaccess` or `ini_set()` cannot turn it back on. That makes scanners and customers see what the detach
already enforces.

### Why you still install the official packages

The one thing the module does not do is replace the engine. The patched release changes the memory allocator and OPcache from the inside;
a module can mirror what those changes achieve, and since v3.1.0 it does so for every path the
advisories and the fix describe, but it remains a layer around the engine rather than the engine
itself. We recommend the official packages, and the module says so itself when it finds them. Until
they are installed, and on installs where they never will be, this is protection you can rely on
rather than a stopgap; afterwards it costs nothing to leave in place.

On `memory_limit=-1` the headroom guard has nothing to guard and is inert; with the module loaded a
finite `memory_limit` is fine, so you do not need the advisories' `memory_limit=-1` workaround unless
you want the belt-and-braces of `force_unlimited_memory`.

Two implementation notes. The stop flag is one static per process, which is exact for NTS builds (all
prebuilt files); a ZTS build from source could, in theory, see a spurious 413 on a concurrent thread.
And php-fpm reads at most `CONTENT_LENGTH` bytes of body on its own, so the no-Content-Length strategy
never reaches the parser through FPM; that one is mod_php's (Apache hands the parser a chunked body
whole), and it is the strategy the advisory's confirmed exploit used.

### Install

```ini
extension=hp_uploadprogress_guard.so
```

That is the whole configuration; the defaults are everything described above, and
`force_unlimited_memory` is the only opt-in. Prebuilt NTS x86_64
binaries per PHP minor are in `dist/` with `SHA256SUMS`; `build.sh` rebuilds them from the official
Docker images; `src/` has the one C file and the per-branch parser copies. Verify with
`php --ri hp_uploadprogress_guard`: it reports whether the handler is detached, whether the carried
parser is active, and whether the running PHP already carries the official fix.

### Optional: emergency switch

`hp_uploadprogress_guard.mode = block` refuses every `multipart/form-data` request before PHP reads
the body (415, empty `$_POST`/`$_FILES`; `allow_ips` lists clients that are still parsed). It costs
all uploads and multipart forms, so it is only for an environment under active attack that cannot
patch yet. All settings are `PHP_INI_SYSTEM`.

* `src/`: one C file plus `config.m4`, and `src/rfc1867/` with the per-branch parser copies.
* `dist/`: prebuilt NTS x86_64 `.so` per PHP minor with `SHA256SUMS`.
* `build.sh`: rebuilds `dist/` from the official `php:<X.Y>-cli` images.
* `test/`: `oom-test.sh` + `oomclient.php` + `mem-probe.php` (the three OOM strategies of the advisory,
  without and with the module: `docker run --rm -v $PWD/dist:/out:ro -v $PWD/test:/t:ro php:8.4-cli bash /t/oom-test.sh`),
  `test-modes.sh` (parse vs block, detach), `run-builtin-server.sh`, `fcgi-probe.py`, `fcgi-lie.py`, `probe.php`.
* `ansible/`: the task files and ini templates Hosted Power deploys (Debian/Sury, cPanel EA4, DirectAdmin).

Tests, v3.0.0, 21 October 2026, official `php:<X.Y>-cli` images, built-in server with
`memory_limit=32M post_max_size=64M`. Each of the advisory's strategies reproduces the out-of-memory
bailout without the module and ends in a 413 drop with it, after which the same server serves a normal
upload: a 40 MB form field, 20 MB of continuation lines in one part header, and 150 000 empty file
controls with nested names (`Allowed memory size exhausted` without; `413 post=0 files=0` and one
`hp_uploadprogress_guard: multipart body dropped` log line with), on 8.4, 8.1, 7.4 and 5.6 in full and
on 7.0 to 7.3, 8.0, 8.2, 8.3 and 8.5 for the field and header cases. No false positives: an 8 MB field
on `memory_limit=128M` is a normal `200 post=1`, and so is a 40 MB field on `memory_limit=-1`. Normal
uploads (two fields and a 100 KB file) parse identically with and without the module on all twelve
versions. mod_php, `php:8.4-apache` (prefork, the SAPI the advisory validated its exploit on): a
chunked 40 MB body without Content-Length against `post_max_size=1M memory_limit=32M` is a startup
out-of-memory fatal (HTTP 500) without the module and a `200` with the body cut at 1 MB and the
`Actual POST length does not match Content-Length` warning with it. php-fpm, `php:8.4-fpm` with a
FastCGI client declaring `CONTENT_LENGTH=1000` and streaming 40 MB: FPM stops reading at 1000 bytes
with or without the module.

Tests, v2, 21 October 2026: parse mode behaves identically to PHP's parser on 8.4 (nested fields,
unicode, awkward filenames, file arrays, checksum of the uploaded file, malformed body); block mode
gives 415 with empty `$_POST`/`$_FILES`, urlencoded 200, GET 200, `ini_set` cannot override; builds
and loads on 5.6 to 8.5; live on cPanel EA4 (8.1 to 8.4) and DirectAdmin CustomBuild (8.2 to 8.4)
staging hosts, block mode exercised end to end on DirectAdmin (multipart 415, urlencoded 200, GET 200,
then back to parse: 200).

---

The sections below describe v1 (the detach alone) and why it was built. They are kept for the
record; read the table above for what applies now.

## Why we built it

**Timeline.** On 20 October 2026 the PHP security team pre-announced two critical vulnerabilities
(CVSS v4.0 9.2 each) with a fix release scheduled for 21 October 14:00 UTC, details withheld. During
the night technical details leaked, and a researcher who reproduced both placed them in the
session extension's upload-progress handler, the code that runs on every `multipart/form-data`
request before any application code. Reports put the affected range at every PHP release since 5.4.

**Our situation.** A managed hosting fleet with roughly 640 hosts declaring PHP, 14 distinct minor
versions from 5.4 to 8.5 side by side, about 200 hosts carrying at least one branch that is end of
life. Three platforms: Debian/Ubuntu with Sury packages, cPanel EA4, DirectAdmin CustomBuild. Several
hundred customer applications we do not control.

**Why the usual advice was not enough for us.**

* *Wait for the packages.* Supported branches would get them within hours (Sury even backports to
  7.4/8.0/8.1), but 5.6 to 7.3 never will, and panel vendors lag by days.
* *Block multipart at the web server.* Breaks every upload form, every media library, Contact Form 7
  submissions. Not an option on shared infrastructure.
* *Set `session.upload_progress.enabled = Off`.* Correct target, wrong lever: it is a per-directory
  ini setting any customer can flip back from `.user.ini`, `.htaccess` or `ini_set()`, and the
  check lives inside the vulnerable function rather than in front of it. See
  [Why this beats the ini setting](#why-this-beats-the-ini-setting).

We wanted something that makes the affected code **unreachable**, on every SAPI, for every
installed version, that customers cannot undo, that keeps uploads working, and that can be
verified per process rather than per config file. The extension does that.

## How it works

Everything below refers to the `PHP-8.3` branch of php-src; the same structure exists from 5.4 to
master.

1. The multipart parser (`main/rfc1867.c`) talks to interested extensions through one global
   function pointer, declared `NULL`:

   ```c
   PHPAPI zend_result (*php_rfc1867_callback)(unsigned int event, void *event_data, void **extra) = NULL;   /* rfc1867.c:52 */
   ```

   Every one of its seven call sites is guarded: `if (php_rfc1867_callback != NULL) { ... }`
   (rfc1867.c:759, 861, 883, 957, 1007, 1076, 1259). A `NULL` pointer means "nobody is listening",
   and the parser just parses.

2. The session extension installs its handler into that pointer at module init
   (`PHP_MINIT_FUNCTION(session)`, session.c:2901-2902):

   ```c
   php_session_rfc1867_orig_callback = php_rfc1867_callback;
   php_rfc1867_callback = php_session_rfc1867_callback;
   ```

   and takes it out again at module shutdown (session.c:2928-2932).

3. `hp_uploadprogress_guard` declares an optional module dependency on `session`
   (`ZEND_MOD_OPTIONAL("session")`), so the engine starts it *after* session. Its `MINIT` then does:

   ```c
   if (php_rfc1867_callback != NULL) {
       php_rfc1867_callback = NULL;
       hp_upg_detached = 1;
   }
   ```

   From that moment the parser's `NULL` checks skip the session extension on every multipart
   event. `php_session_rfc1867_callback` is never entered again in that process.

4. `MINFO` reports what happened, so `php --ri hp_uploadprogress_guard` (or `phpinfo()`) shows
   `rfc1867 (session.upload_progress) callback detached => yes` in the running build.

That was the whole extension in v1, and it is still the core: one pointer write at process start. v2
added the carried parser, v3 the memory-headroom guard, v3.1 the out-of-memory exit, the request-state
reset and the OPcache compile window described in the release notes above. There are still no opcode
changes and no per-request cost worth measuring.

## Effect

| | Before | After |
|---|---|---|
| File uploads, `$_FILES`, `$_POST`, multipart forms | work | work, unchanged |
| Sessions, `session_start()`, save handlers | work | work, unchanged |
| `session.upload_progress` feature (`$_SESSION["upload_progress_<name>"]` filled while a file is uploading) | works | **off**, nothing is written |
| `ini_get('session.upload_progress.enabled')`, `phpinfo()` | `1` | `0` / `Off`, locked (since v3.0.2) |
| Process restart needed | | php-fpm / mod_php once; cgi and cli pick it up on the next start |

The upload-progress feature is the only casualty. Browsers have reported upload progress natively
(`XMLHttpRequest.upload.onprogress`) since 2012, and every mainstream application uses that, so in
practice the feature is dormant. An application that still polls `$_SESSION` for progress simply
sees no entry: the upload itself completes normally.

## Why this beats the ini setting

`session.upload_progress.enabled = Off` is what every advisory suggests. It targets the same code,
so it is not wrong. It is weaker in four concrete ways.

**1. The ini can be re-enabled from below you; the guard cannot.**
`session.upload_progress.enabled` is declared `ZEND_INI_PERDIR` with a compiled-in default of `1`
(session.c:849-850). `PERDIR` means every per-directory layer may set it: a `.user.ini` in any
customer docroot (CGI/FastCGI), `php_flag` in `.htaccess` (mod_php), `php_value` in a pool file. An
`=Off` in `conf.d` is silently undone by one line in one site. The only ini form that locks it is
`php_admin_flag` in every FPM pool, which still leaves CLI, CGI and mod_php uncovered. The guard
writes `NULL` into a C function pointer at module init. No ini layer, no `ini_set()`, no application
code has a way to write that pointer back.

**2. The ini gate sits inside the handler; the guard sits in front of it.**
With the ini off, the parser still calls into the session extension on every multipart event, and
the handler returns early *after* consulting the flag (session.c:3103-3108: it first forwards to a
chained callback, then `if (!PS(rfc1867_enabled)) return retval;`). Any code before that check, or a
future change that moves the check, still runs. With the guard, the parser's own `NULL` test skips
the call: the session extension never sees a multipart event at all.

**3. One mechanism covers every SAPI and every installed version.**
`phpenmod -s ALL` (Debian), a `php.d` drop-in (EA4), a `php.conf.d` drop-in (CustomBuild) loads the
guard into fpm, cli, cgi and apache2 for every discovered version, including a phpMyAdmin-only one.
The ini equivalent is a mix of `php_admin_flag` per pool, `conf.d` for CLI, `php_admin_flag` in
Apache vhosts for mod_php, each with its own way to be missed.

**4. It is verifiable per process, not per config file.**
`php --ri hp_uploadprogress_guard` reports whether the callback was actually detached in the
running build, and `grep hp_uploadprogress_guard /proc/<fpm-master-pid>/maps` shows it is mapped in
the live master. An ini value only tells you what one file says, not what won after all layers were
merged.

The ini setting stops at that handler. The module started there in v1 and, release by release, took on
the rest of what the official fix does: the hardened parser, the memory headroom, the out-of-memory
exit, the request-state reset and the OPcache compile window. That is the difference in coverage, on
top of the difference in mechanism.

## Compatibility

* **PHP versions:** 5.4, 5.5, 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1, 8.2, 8.3, 8.4, 8.5 (one source
  file, no per-version patches). 5.4 and 5.5 use the 5.6 parser copy, which `config.m4` and `config.w32`
  pick automatically; their prebuilt files are made by `build-legacy.sh`, which compiles PHP 5.4.45 /
  5.5.38 from the php.net source archives (no official Docker image exists) and builds the module against
  them, with the same tests and the same glibc gate as the others. Old patch releases of a branch (7.4
  before 7.4.14, 8.0.0) build too: the parser copies carry a compat define for the temp-file flag those
  releases lack.
* **ABI:** a PHP extension's ABI is the Zend module API number of the minor version plus the NTS/ZTS
  flavour (checked at load time). The prebuilt files are NTS x86_64 and load on any NTS build of that
  minor: Sury, Remi, cPanel EA4, DirectAdmin CustomBuild, the official Docker images. ZTS builds need
  a rebuild from source.
* **Thread-safe SAPIs** (Apache `mod_php` with mpm_winnt, worker or event; the Windows `ts` DLLs): the
  multipart handler is installed per thread since v3.2.3; earlier versions only covered the startup thread
  there, which phpinfo did not show. On a threaded SAPI, check phpinfo through the web server, not `php --ri`.
* **Other extensions that replace the POST handlers** (Suhosin, and anything that registers post entries
  from a Zend-extension startup hook): they install after every module's MINIT and therefore win, in any
  load order; the module does not fight that. Suhosin's own multipart parser then handles the body with
  Suhosin's limits, `--ri`/phpinfo reports "handler replaced => no (another extension installed its own
  handler in this thread)", and the other layers stay active. Measured with the NewEraCracker Suhosin fork
  on PHP 5.6 (#14).
* **CPU architecture:** prebuilt files for x86_64 and aarch64 (arm64), both built on the same old-glibc
  images (`build.sh`, `ARCHS="x86_64 aarch64"`, aarch64 under QEMU). Highest glibc symbol version required:
  `GLIBC_2.3` on x86_64 (`memcpy` is bound to its original symbol version in `src/hp_glibc_compat.h`, so
  CentOS 6, Debian 6 and anything newer load the files; verified against the stock PHP 5.4.16 of CentOS 7),
  `GLIBC_2.17` on aarch64 (that architecture's baseline, EL7 aarch64 and newer). The code has nothing
  architecture-specific. Windows x64 DLLs come from the CI workflow (`dist/windows/`).
* **libc:** since v2 the binaries carry the multipart parser and therefore do import versioned glibc
  symbols. They are built on the oldest Debian image that ships each minor (stretch for 5.6 to 7.3,
  buster for 7.4 to 8.1, bullseye for 8.2 to 8.4, bookworm for 8.5) and `build.sh` refuses any file
  that needs more than `GLIBC_2.14` (`objdump -T`), so they load on Debian 8+, Ubuntu 14.04+ and EL 7+.
  Do not rebuild them on a glibc 2.38+ host without that check: `strtoll` then binds to
  `__isoc23_strtoll@GLIBC_2.38` and the file refuses to load on anything older.

## Install

Every version is published as a [GitHub Release](https://github.com/HOSTED-POWER/php_uploadprogress_guard/releases/latest)
with one download: `hp_uploadprogress_guard-<version>.zip` (or `.tar.gz`, same content), holding every Linux `.so`
and Windows DLL, the ini files, the source, `install_guard.sh` and an `INSTALL.txt` with the steps per platform,
all covered by a `SHA256SUMS` inside. The single files are also in `dist/` on `main`. Watch the repository with
"Custom > Releases" to be notified of new versions.

### Build from source (any PHP, any flavour)

```sh
cd src && phpize && ./configure && make
# -> modules/hp_uploadprogress_guard.so ; `make install` drops it in extension_dir
```

If `make` stops with `libtool: Version mismatch error` (PHP 5.x phpize ships older libtool macros than the
system libtool, seen on Gentoo, #13), regenerate the build files once after `phpize`:
`libtoolize --copy --force && aclocal && autoreconf --force --install`, then `./configure && make` again.

### Prebuilt (Linux)

`dist/` holds one NTS build per PHP minor and CPU architecture, with `SHA256SUMS`:

* x86_64: `dist/hp_uploadprogress_guard-<X.Y>.so`
* arm64 (aarch64, e.g. Graviton, Ampere, Raspberry Pi OS 64-bit): `dist/hp_uploadprogress_guard-<X.Y>-aarch64.so`

Pick the file for your minor version and `uname -m`, copy it to `php -n -r 'echo PHP_EXTENSION_DIR;'` as
`hp_uploadprogress_guard.so`, and add an ini with `extension=hp_uploadprogress_guard.so` to the scan dir of every
SAPI (the snippets below do exactly that; on arm64 add `-aarch64` to the file name). The Ansible task files pick
the architecture from `ansible_facts['architecture']`.

### Windows

`dist/windows/` holds a DLL per PHP minor (5.4, 5.6, 7.2 to 8.5), thread safety and compiler, with `SHA256SUMS`:
`php_hp_uploadprogress_guard-<X.Y>-<nts|ts>-<vc9|vc11|vc15|vs16|vs17>-<x64|x86>.dll`, 64-bit and 32-bit. The 7.2 to
8.5 files are built by the `Windows build` workflow in this repository with the PHP team's
[php-windows-builder](https://github.com/php/php-windows-builder); in the same run the x64 nts ones are loaded
into a stock Windows PHP and every x86 one into the official windows.php.net x86 build of its branch
(`--ri` output in the job log). The 5.6 files (VC11, x64 and x86, nts and ts) come
from the `Windows build PHP 5.6 (VC11)` workflow: Visual Studio 2012 Express is installed on the runner from
Microsoft's ISO, PHP 5.6.40 is built in-tree with the extension as a shared module, and every DLL is loaded
into the official 5.6.40 VC11 zip from windows.php.net before it is published. The 5.4 files (VC9, x86, nts and
ts; PHP 5.4 on Windows was only ever released as x86) come from the `Windows build PHP 5.4 (VC9)` workflow: the
Visual C++ 2008 compiler and Windows SDK 6.0A are unpacked from Microsoft's Visual Studio 2008 Express ISO,
PHP 5.4.45 is built in-tree, and every DLL is loaded into the official 5.4.45 VC9 x86 zip. A 5.4.45 build loads
into every 5.4.x (same extension API).

```powershell
php -i | findstr /C:"PHP Version" /C:"Thread Safety" /C:"Compiler" /C:"extension_dir"
# e.g. 8.3.x, Thread Safety => disabled (nts) or enabled (ts), Compiler => Visual C++ 2019 (vs16)
copy dist\windows\php_hp_uploadprogress_guard-8.3-nts-vs16-x64.dll "C:\php\ext\php_hp_uploadprogress_guard.dll"
# then in php.ini:  extension=hp_uploadprogress_guard   and restart IIS / Apache
# PHP 5.6 takes the file name only:  extension=php_hp_uploadprogress_guard.dll  (the bare name needs 7.2+)
php --ri hp_uploadprogress_guard
```

The compiler tag must match your PHP build (`php -i` prints it): vc15 for 7.2 to 7.4, vs16 for 8.0 to 8.3, vs17
for 8.4 and 8.5, which are also the builds windows.php.net ships. Thread safety must match too (IIS FastCGI uses
nts, Apache mod_php uses ts); 5.4 is vc9 (x86 only), 5.6 is vc11, and `php -i` shows `Architecture => x86` or `x64`. PHP 7.0/7.1 on
Windows are not provided; those build from source with the PHP SDK: `phpize && configure --enable-hp-uploadprogress-guard && nmake` from
the repository root (`config.w32` picks the parser copy; PHP 5.x has no phpize on Windows, build in-tree as the
5.6 workflow does). PHP 5.x thread-safe builds compile since v3.2.2.

### Debian / Ubuntu with Sury packages

`install_guard.sh` does the steps below for every PHP version under `/etc/php` (or the ones you name with
`--php X.Y`), x86_64 or arm64. It downloads the module for each version, checks it against `SHA256SUMS`,
loads it in a separate PHP process first, swaps the `.so` in atomically, and installs the ini only if none
is there yet, so a `mode` or `allow_ips` you set survives updates. Without `--reload` it touches no running
service: the module is active for the CLI at once and for PHP-FPM / Apache after their next reload. With
`--reload` it runs `php-fpmX.Y -t` / `apache2ctl -t`, reloads gracefully, and then checks that the running
master really has the module loaded. Re-run it to update; `--remove` undoes everything. The checksum
catches a broken download, not a compromised source: read the script, and pin `--ref` to a commit you
reviewed.

```sh
curl -fsSLO https://raw.githubusercontent.com/HOSTED-POWER/php_uploadprogress_guard/main/install_guard.sh
less install_guard.sh
sudo bash install_guard.sh --reload                       # or: --php 8.3, --ref <commit>, --remove
```

Run from an unpacked release bundle, it installs the files next to it and downloads nothing (servers without
internet access): `tar xzf hp_uploadprogress_guard-<version>.tar.gz && sudo bash hp_uploadprogress_guard-<version>/install_guard.sh --reload`.

By hand, per version:

```sh
V=8.3
install -m 0644 dist/hp_uploadprogress_guard-$V.so "$(php$V -n -r 'echo PHP_EXTENSION_DIR;')/hp_uploadprogress_guard.so"
install -m 0644 ansible/mods-available-hp_uploadprogress_guard.ini /etc/php/$V/mods-available/hp_uploadprogress_guard.ini
phpenmod -v $V -s ALL hp_uploadprogress_guard      # the ini is just "; priority=20" + "extension=hp_uploadprogress_guard.so" plus commented defaults
systemctl restart php$V-fpm        # and apache2 if you run mod_php
```

### cPanel EA4

```sh
for root in /opt/cpanel/ea-php*; do
    [ -x "$root/root/usr/bin/php" ] || continue
    v=$(basename "$root" | sed -E 's/^ea-php([0-9])([0-9]+)$/\1.\2/')
    install -m 0644 "dist/hp_uploadprogress_guard-$v.so" "$root/root/usr/lib64/php/modules/hp_uploadprogress_guard.so"
    install -m 0644 ansible/20-hp_uploadprogress_guard.ini "$root/root/etc/php.d/20-hp_uploadprogress_guard.ini"
done
/scripts/restartsrv_apache_php_fpm   # cgi/lsapi SAPIs need no restart
```

### DirectAdmin CustomBuild

```sh
for bin in /usr/local/php[0-9]*/bin/php; do
    d=$(dirname "$(dirname "$bin")"); v=$(basename "$d" | sed -E 's/^php([0-9])([0-9]+)$/\1.\2/')
    install -m 0644 "dist/hp_uploadprogress_guard-$v.so" "$("$bin" -n -r 'echo PHP_EXTENSION_DIR;')/hp_uploadprogress_guard.so"
    install -m 0644 ansible/20-hp_uploadprogress_guard.ini "$d/lib/php.conf.d/20-hp_uploadprogress_guard.ini"
    systemctl restart "php-fpm${v/./}"
done
```

Re-run after a CustomBuild PHP rebuild, or hook it into `custombuild/custom/hooks/php/post/`.

### Ansible

`ansible/` holds the task files we run in production (they expect the `.so` files under
`files/uploadprogress-guard/` of a role and a `php_uploadprogress_guard_enabled` boolean for the
opt-out/teardown path). They discover installed versions on the host, so nothing is hardcoded.

## Verify

```sh
php -m | grep hp_uploadprogress_guard
php --ri hp_uploadprogress_guard          # expect: ... callback detached => yes
php-fpm8.3 -m | grep hp_uploadprogress_guard
grep -c hp_uploadprogress_guard /proc/$(systemctl show -p MainPID --value php8.3-fpm)/maps   # > 0
```

Since v3.0.2 `session.upload_progress.enabled` reads `Off` as well, but judge by `--ri`: it lists every
mechanism (handler detached, parser replaced, headroom guard, out-of-memory exit, request-state reset,
OPcache compile window, `memory_limit` lock) with `active`, `not needed (engine carries the fix)` or
the effective value when a pool directive overrode it.

End to end: put `test/probe.php` in a docroot and run `python3 test/fcgi-probe.py <fpm socket>
<path to probe.php>`. Expected: `files=1 size=200000 err=0` and `session_keys=` (empty). Without the
guard the last line reads `session_keys=upload_progress_probe`.

## Remove

Delete the ini (`phpdismod hp_uploadprogress_guard` on Debian) and the `.so`, restart php-fpm. The
Ansible task files do this when `php_uploadprogress_guard_enabled: false`.

## Tests performed (21 October 2026)

All runs below were done before the fleet rollout; outputs are verbatim.

**1. Build and load on every supported minor** (`build.sh`, official `php:<X.Y>-cli` images). Each
version printed `LOADED` and `rfc1867 (session.upload_progress) callback detached => yes`:
8.5.11, 8.4.26, 8.2.34, 8.1.34, 8.0.30, 7.4.33, 7.3.33, 7.2.34, 7.1.33, 7.0.33, 5.6.40 (8.3.35 first,
by hand).

**2. Functional test, built-in server, PHP 8.3** (`test/run-builtin-server.sh 8.3`; the probe printed `guard_loaded`/`upload_progress_ini` at the time, now `guard`/`ini`):

```
===== without guard: multipart upload WITH progress field + session cookie
guard_loaded=0  upload_progress_ini=1
post_keys=PHP_SESSION_UPLOAD_PROGRESS,name
files=1 size=300000 err=0
session_keys=upload_progress_probe
===== with guard: multipart upload WITH progress field + session cookie
guard_loaded=1  upload_progress_ini=1
post_keys=PHP_SESSION_UPLOAD_PROGRESS,name
files=1 size=300000 err=0
session_keys=
```

Same request, same ini, same upload: the progress entry disappears, nothing else changes.

**3. Binary hygiene** (`readelf --dyn-syms`, `readelf -V`): undefined symbols are
`php_rfc1867_callback`, `php_info_print_table_start/row/end`, `__cxa_finalize`, `__gmon_start__`,
`_ITM_*`. No `GLIBC_*` version requirements.

**4. Real Sury build, php-fpm SAPI** (Debian 13, Sury php8.4-fpm 8.4.26): `.so` loaded with
`php -n -d extension=`, reported detached. Then `test/fcgi-probe.py` against
`/run/php/php8.4-fpm.sock`:

```
sapi=fpm-fcgi guard=1 ini=1
post=PHP_SESSION_UPLOAD_PROGRESS,name files=1 size=200000 err=0
session_keys=
```

and `grep -c hp_uploadprogress_guard /proc/<master pid>/maps` = 5.

**5. Real panel builds**: cPanel EA4 `ea-php83` 8.3.35 on AlmaLinux 10.2 (glibc 2.39) and
DirectAdmin CustomBuild `php84` 8.4.22 on Debian 13 both loaded the prebuilt file and reported
detached. On cPanel a fresh `php-cgi -m` (the SAPI those hosts use) lists the module.

**6. Ansible rollout validation** (tag-scoped `phpguard` runs with the fleet playbook, then a second
run for idempotency, then a full untagged deploy on the Debian test host):

| Host | Platform | Versions guarded | Result |
|---|---|---|---|
| ansibletest | Debian 13 / Sury | 8.4 | `failed=0`, second run `changed=0`, full deploy `ok=1506 failed=0` |
| web1, web2, web3 | Debian / Sury, via AWX | 8.3+8.4, 7.4+8.3+8.4, 8.4 | `changed=4` each, fpm restarted, idempotent re-run |
| cpanel1.staging | cPanel EA4, AlmaLinux 10 | 8.1, 8.2, 8.3, 8.4 | `failed=0`, second run `changed=0` |
| directadmin1.staging | DirectAdmin CustomBuild, Debian | 8.2, 8.3, 8.4 | `failed=0`, second run `changed=0`, all three fpm restarted |

Per host afterwards: every version's `php -m` lists the module, `--ri` says detached, fpm masters
map the library, conf.d/php.d/php.conf.d carry the ini.

**7. v3.1.0** (21 October 2026, evening; official `php:<X.Y>-cli` and `-fpm` images, Sury packages
of the same day; outputs verbatim, exit codes from the shell).

One multipart body of 15 000 fields, php-cgi, unpatched 8.4.11, 8.1.20, 7.0.33 and 5.6.40, identical
on all four. `memory_limit` was set to 2M only so that a small body reaches the limit; every mechanism
is relative to the limit in force (the headroom guard keeps an eighth of it free, the out-of-memory
exit reacts to the engine's own error at any size), so the results are the same at 128M or 2G, the
body just has to be proportionally larger:

| | exit | meaning |
|---|---|---|
| no module | 255 | `Allowed memory size exhausted` during request startup |
| `mode=native` | **137** | out-of-memory exit: the process ends instead of serving another request |
| `mode=parse` (default) | 0, `Status: 413` | headroom guard, no out-of-memory at all |
| `mode=native` + `force_unlimited_memory=1` | 0, `OK:15000` | no limit to hit |
| script-phase OOM (`-r` loop) | 255, `Fatal error` | PHP behaviour unchanged |

Genuine operating-system out-of-memory (`ulimit -v 90000`, `force_unlimited_memory=1`, 400 000-part
body, 8.4): no module exit 255 with `Out of memory`, module exit 137.

php-fpm, one static worker, GET, then the OOM POST with a file part, then GET (8.4.11, 7.4.33, 5.6.40):
`mode=native` worker respawned (`child exited with code 137`), 0 orphaned upload temp files (stock PHP
leaves 1 behind after its own startup failure, `code 70`); `mode=parse` answers `413`, same worker
reused, 0 temp files. A 15 000-field POST to a script with `set_error_handler`, an undefined variable
and `trigger_error`: `OK:15000 handled: … handled: custom` on 8.4 and 5.6, so handlers and warnings are
untouched by the request-state reset.

OPcache compile window (8.4.11, OPcache on, `memory_limit=20M`, a 5.5 MB script compiled for the first
time with a 9 MB POST in memory): no module `Allowed memory size … in Unknown on line 0` (inside
OPcache's store); module `compiled+ran, memory_limit=20M`, second request served normally.

Fix detection: Sury 5.6.40-104, 7.0.33-92, 7.3.33-35, 7.4.33-31, 8.1.34-9 and 8.3.36-1 all report
`carries the official fix => yes (fix symbol exported by the engine; parser replacement skipped)` and
`out-of-memory exit => not needed`; docker 8.4.11, 8.1.20, 7.4.33, 5.6.40 report `no` with every
mechanism `active`. Neither fix symbol exists on any unpatched engine (`nm -D`).

All 12 binaries: zero compiler warnings, nothing above `GLIBC_2.14`, the fix probes appear as
versionless weak references (`objdump -T`).

**8. v3.2.0** (22 October 2026; official `php:<X.Y>-cli` and `-fpm` images, PHP built from the php.net
release archives where an image was missing; outputs verbatim).

Valgrind memcheck (`USE_ZEND_ALLOC=0`), six reproducers: both paths from the public report (an object
dropped by a duplicate key, the return value of `__wakeup()`), and the same nested call made through
`call_user_func()`, through an explicit `Serializable::unserialize()` inside the destructor, and from a
generator's `finally` block:

| PHP | without module | with v3.2.0 | behaviour suite under Valgrind |
|---|---|---|---|
| 8.5.12 | `Invalid read of size 8` in `php_var_unserialize`, all six | clean, all six | 20/20, 0 errors |
| 8.4.27 | same | clean, all six | 20/20, 0 errors |
| 8.3.36 | same | clean, all six | 20/20, 0 errors |
| 8.2.35 | same | clean, all six | 20/20, 0 errors |
| 7.4.33 | same, in `zif_unserialize` | clean, all six | 18/18, 0 errors |
| 5.6.40 | not reached (different code path on 5.x) | clean | 15/15, 0 errors |

Without Valgrind the bug is silent: on stock 7.0 to 8.5.12 the nested call returns data read from the freed
chunk (`array(0 => 0)` where it should fail); with v3.2.0 it fails cleanly (`false`).

Behaviour suite (a self-checking PHP script, 14 to 20 cases depending on the branch: scalars, references,
`Serializable` nesting with shared back-references, through a helper and two levels deep, `__wakeup()` and
`__unserialize()` that unserialize, destructors, autoloaders, sessions through `session_decode()` and the
files handler, `SplObjectStorage`/`ArrayObject`/`DateTime`/`SplQueue`, enums, readonly classes, fibers,
generators, a 20 000-element payload): every case passes on 5.4, 5.5, 5.6, 7.0 to 7.4 and 8.0 to 8.5, and
the output with the module is byte-identical to the output without it. The two changed cases (see the
v3.2.0 note) are correct with the module on every branch; without it they are wrong or fatal on stock 7.0 to 8.5.

PHP's own test suites (`ext/standard/tests/serialize`, `ext/session/tests`, 306 to 433 `.phpt` per branch)
on 5.6, 7.0, 7.4, 8.2, 8.4 and 8.5: the results with v3.2.0 are identical to v3.1.0. The only tests that
differ from a PHP without the module are the eight `ext/session/tests/rfc1867*.phpt`, which test the
`session.upload_progress` feature this module has switched off since v1.

OPcache with tracing JIT on 8.5 and 8.4, CLI and php-fpm: suite identical with and without the module,
reproducers clean, the php-fpm worker serves the suite again after the reproducer, no crashes. Cost
(8.4, one CPU, median of five alternating runs of 300 000 calls): top-level `unserialize()` 349 ns
without, 378 ns with (within run-to-run noise); nested inside `Serializable::unserialize()` 423 ns
without, 474 ns with.

Staging, through the fleet Ansible role: DirectAdmin CustomBuild 8.2.35, 8.3.36, 8.4.27 and cPanel EA4
8.1.34, 8.2.34, 8.3.35, 8.4.26 all report 3.2.0 with the isolation active, a live destructor-time check
returns the isolated (correct) result on every version, and the php-fpm masters map the module.

Build: 28 Linux binaries (x86_64 and aarch64, 5.4 to 8.5) with zero compiler warnings, x86_64 needing at
most `GLIBC_2.3`, aarch64 at most `GLIBC_2.17`.

**9. v3.2.1** (22 October 2026; PHP 8.2.35, 8.3.36, 8.4.26, 8.4.27 and 8.5.12 built from the php.net release
archives with SimpleXML; Valgrind with `USE_ZEND_ALLOC=0`).

| PHP | reproducer without module (three trigger styles) | with v3.2.1 |
|---|---|---|
| 8.4.26 | clean | clean (workaround off: not needed) |
| 8.4.27 | `Invalid read` | clean |
| 8.5.12 | `Invalid read` | clean |
| 8.3.36, 8.2.35 | clean | clean (not needed) |

A SimpleXML behaviour script (the `json_decode(json_encode())` idiom, `get_object_vars()`, casts, attributes and
namespaces, iteration, XPath, `count()`, clones, `addChild()`, `asXML()`, a `SimpleXMLElement` subclass,
`SimpleXMLIterator`, `dom_import_simplexml()`, 2 000 objects in collected cycles) aborts with `zend_mm_heap
corrupted` on stock 8.4.27 and 8.5.12; with v3.2.1 it completes, its output is byte-identical to stock 8.4.26,
and it is clean under Valgrind. PHP's own `ext/simplexml` tests (164 and 165 `.phpt`): per-test results
identical with and without the module, 0 failures. php-fpm with tracing JIT on 8.5.12: the script three times
in one worker, identical results, no crash. The v3.2.0 checks (unserialize reproducers, behaviour suite) are
unchanged. On a DirectAdmin staging host with 8.4.27 the script crashed with v3.2.0 and completed with v3.2.1.

## Repository layout

```
src/        hp_uploadprogress_guard.c, config.m4, rfc1867/ (per-branch parser copies)
config.w32  Windows build file (PHP SDK / php-windows-builder)
dist/       prebuilt NTS .so per PHP minor for x86_64 and aarch64 + SHA256SUMS
dist/windows/  DLL per PHP minor (7.2-8.5), nts/ts, x64 + SHA256SUMS, from the CI workflow
build.sh    rebuild dist/ from the oldest official php:<X.Y>-cli images, both architectures
test/       probe.php, run-builtin-server.sh (Docker functional test), fcgi-probe.py (php-fpm direct)
ansible/    the task files and ini files we deploy (Debian/Sury, cPanel EA4, DirectAdmin)
```

## License

MIT. Built by Hosted Power. Use it, audit it, rebuild it; and install the official PHP packages as
soon as your vendor ships them.
