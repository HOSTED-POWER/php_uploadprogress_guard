/*
 * hp_uploadprogress_guard - owns PHP's multipart/form-data post handler.
 *
 * At MINIT the SAPI post entry for multipart/form-data (main/rfc1867.c's handler) is replaced by
 * ours. Two modes, selected by the INI_SYSTEM setting hp_uploadprogress_guard.mode:
 *   parse  (default) hand the request to the copy of main/rfc1867.c compiled into this module
 *                    (rfc1867_copy.c): the parser of the fixed PHP release, with ext/session's
 *                    upload-progress callback compiled out and, since v3, a memory-headroom guard
 *                    that stops the request (413, $_POST/$_FILES dropped) before any step could
 *                    exhaust memory_limit, so no out-of-memory bailout can start inside the parser.
 *   native           leave PHP's own parser in place (use once the patched PHP packages are installed);
 *                    "off" is not usable as a value because PHP's ini parser turns it into ""
 *   block            refuse the request before any parsing: the body is never read, $_POST and
 *                    $_FILES stay empty, the response code is set to 415 and a warning is logged.
 *                    Emergency mode for CVE-2026-109618 / CVE-2026-109619 while no fix exists.
 * hp_uploadprogress_guard.allow_ips: comma separated client IPs that are always parsed (admins, monitoring).
 * hp_uploadprogress_guard.detach_upload_progress (default 1): at MINIT, after ext/session has started, drop
 *   ext/session's multipart upload-progress handler (php_session_rfc1867_callback) from main/rfc1867.c's
 *   callback pointer, so that handler is unreachable whatever session.upload_progress.* says.
 * hp_uploadprogress_guard.force_unlimited_memory (default 0): at MINIT, set the master value of memory_limit
 *   to -1 (no limit) and lock it to PHP_INI_SYSTEM: .user.ini, .htaccess, PHP_VALUE and ini_set() cannot
 *   lower it again, so the memory_limit bailout (the longjmp CVE-2026-109618 relies on) cannot fire at
 *   all, in any parser. Bound the process with the OS instead (cgroup MemoryMax, RLIMIT_AS). Limits:
 *   php-fpm pool directives (php_value / php_admin_value [memory_limit]) and PHP_ADMIN_VALUE are written
 *   by FPM after this module started and take precedence; phpinfo()/--ri show the effective value.
 * All settings are PHP_INI_SYSTEM: php.ini / php-fpm.conf only, never .user.ini, .htaccess or ini_set().
 *
 * Out-of-memory exit (CVE-2026-109618 defense in depth, unpatched engines only): zend_error_cb is chained;
 * when the allocator reports "Allowed memory size exhausted" or "Out of memory" while no script is executing
 * (EG(current_execute_data) == NULL: request startup, i.e. POST parsing, or request shutdown), the process
 * calls _exit(137) after unlinking the upload temp files registered so far, exactly what the official fix
 * does past its hard memory limit. The bailout PHP would otherwise take skips the cleanup of request state,
 * and a persistent SAPI then serves the next request with stale pointers. php-fpm already discards a worker
 * whose request startup failed (exit code 70), so this matters for mod_php, LiteSpeed, FrankenPHP and any
 * other SAPI that keeps the process, and for memory exhaustion during request shutdown on every SAPI.
 * Stale request state (CVE-2026-109619, the "INI diagnostic" route), unpatched engines only: PHP frees the
 * user error/exception handlers, the superglobals and the request_info strings at request end but leaves
 * the pointers in place until the next request's executor init; a warning raised before that point (an
 * invalid php_value / .htaccess / .user.ini directive, PHP_VALUE) reaches them. The official fix writes
 * safe values right after freeing; this module writes the same values a few steps later, in its
 * post-deactivate function and in a wrapper around the SAPI's deactivate callback. On 8.1+ with OPcache,
 * memory_limit is lifted while OPcache compiles and stores a script (a bailout inside that window would
 * leave OPcache's shared memory and the recorded-errors state inconsistent, which the fix guards by
 * deferring publication; the window cannot run out of memory_limit here instead) and restored afterwards.
 * On 8.5 the saved fatal-error backtrace is cleared at request end as well.
 *
 * Engines carrying the official fix export a symbol the old ones lack: zend_handle_delayed_oom() (8.2+,
 * delayed out-of-memory handled at a safe point) or zend_mm_safe_error_ex() (the 7.4/8.0/8.1 "minimal
 * mitigation", where the allocator _exit()s on every memory exhaustion instead of bailing out). When either
 * is present, also in vendor backports that keep the old version number, the engine is treated as patched:
 * no hook, and mode=parse steps aside as described above.
 *
 * mbstring: its multibyte hooks (encoding detection, mb-aware getword/basename) are file-static in mbstring
 * and registered into PHP's own rfc1867.c only, so the carried parser cannot run them. They are used solely
 * when mbstring.encoding_translation is On (PHP_INI_PERDIR), so such a request is handed to PHP's native
 * parser instead (the callback detach still applies to it); everything else is byte-identical.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "hp_glibc_compat.h"
#include "hp_uploadprogress_guard.h"
#include "php_ini.h"
#include "zend_ini.h"
#include "ext/standard/info.h"
#include "SAPI.h"
#include "rfc1867.h"
#include "ext/standard/php_versioning.h"
#include "zend_extensions.h"
#include "zend_interfaces.h"
#include "ext/standard/basic_functions.h"
#include <string.h>
#include <stdarg.h>
#ifdef PHP_WIN32
#include <io.h>
#include <process.h>
#include <windows.h>
#define HP_UPG_UNLINK _unlink
#else
#include <unistd.h>
#define HP_UPG_UNLINK unlink
#endif

/* Probe for the symbols only the fixed engines export (see the header comment).
 * ELF: weak references, left NULL by the dynamic linker on an engine without the fix; local names via
 * asm labels so they never clash with a patched php-src header; no dlsym(), that would bind a glibc version.
 * Windows: GetProcAddress() on the module that exports the engine (php8.dll, php8ts.dll, ...), found
 * from the address of any engine function. */
#ifdef PHP_WIN32
static int hp_upg_engine_exports(const char *name)
{
	HMODULE m = NULL;
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCSTR) (void *) zend_hash_find, &m) || !m) {
		return 0;
	}
	return GetProcAddress(m, name) != NULL;
}
#define hp_upg_sym_delayed_oom   (hp_upg_engine_exports("zend_handle_delayed_oom") ? (void *) 1 : NULL)
#define hp_upg_sym_safe_error_ex (hp_upg_engine_exports("zend_mm_safe_error_ex") ? (void *) 1 : NULL)
#else
extern void hp_upg_sym_delayed_oom(void) __asm__("zend_handle_delayed_oom") __attribute__((weak));
extern void hp_upg_sym_safe_error_ex(void) __asm__("zend_mm_safe_error_ex") __attribute__((weak));
#endif

#define HP_MPG_VERSION "3.2.5"
#define HP_MPG_NAME "hp_uploadprogress_guard"

/* thread-safe (ZTS) builds, PHP 7+: per-thread globals cache (no-op on NTS) */
#if defined(ZTS) && PHP_VERSION_ID >= 70000
ZEND_TSRMLS_CACHE_DEFINE()
#endif
/* thread-safe (ZTS) builds, PHP 5: a function without a TSRMLS_D parameter fetches the thread context itself
 * (a declaration: last line of the function's declaration block). No-op on NTS and on PHP 7+. */
#if defined(ZTS) && PHP_VERSION_ID < 70000
#define HP_UPG_TSRMLS_FETCH() TSRMLS_FETCH()
#else
#define HP_UPG_TSRMLS_FETCH()
#endif
#if PHP_VERSION_ID < 70000
#define HP_UPG_TSRMLS_D TSRMLS_D
#define HP_UPG_TSRMLS_C TSRMLS_C
#else
#define HP_UPG_TSRMLS_D void
#define HP_UPG_TSRMLS_C
#endif

SAPI_POST_HANDLER_FUNC(hp_rfc1867_post_handler);
static SAPI_POST_HANDLER_FUNC(hp_upg_dispatch);

static sapi_post_entry hp_upg_entry = { MULTIPART_CONTENT_TYPE, sizeof(MULTIPART_CONTENT_TYPE) - 1, NULL, hp_upg_dispatch };
static int hp_upg_want_install = 0; /* decided once at MINIT: mode and whether PHP already carries the fix */

ZEND_DECLARE_MODULE_GLOBALS(hp_uploadprogress_guard)
#ifdef ZTS
# if PHP_VERSION_ID >= 70000
#  define HP_UPG_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(hp_uploadprogress_guard, v)
# else
#  define HP_UPG_G(v) TSRMG(hp_uploadprogress_guard_globals_id, zend_hp_uploadprogress_guard_globals *, v)
# endif
#else
# define HP_UPG_G(v) (hp_uploadprogress_guard_globals.v)
#endif

static int hp_upg_install_entry(HP_UPG_TSRMLS_D)
{
#if PHP_VERSION_ID < 70000
	sapi_unregister_post_entry(&hp_upg_entry TSRMLS_CC);
	return sapi_register_post_entry(&hp_upg_entry TSRMLS_CC) == SUCCESS;
#else
	sapi_unregister_post_entry(&hp_upg_entry);
	return sapi_register_post_entry(&hp_upg_entry) == SUCCESS;
#endif
}

/* Is our handler the one the current thread's SAPI table holds for multipart/form-data right now? */
static int hp_upg_entry_live(HP_UPG_TSRMLS_D)
{
	sapi_post_entry *e;
#if PHP_VERSION_ID < 70000
	if (zend_hash_find(&SG(known_post_content_types), MULTIPART_CONTENT_TYPE, sizeof(MULTIPART_CONTENT_TYPE), (void **) &e) != SUCCESS) {
		return 0;
	}
#else
	e = (sapi_post_entry *) zend_hash_str_find_ptr(&SG(known_post_content_types), MULTIPART_CONTENT_TYPE, sizeof(MULTIPART_CONTENT_TYPE) - 1);
	if (!e) {
		return 0;
	}
#endif
	return e->post_handler == hp_upg_dispatch;
}

static PHP_GINIT_FUNCTION(hp_uploadprogress_guard)
{
#if defined(COMPILE_DL_HP_UPLOADPROGRESS_GUARD) && defined(ZTS) && PHP_VERSION_ID >= 70000
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	hp_uploadprogress_guard_globals->entry_installed = 0;
	hp_uploadprogress_guard_globals->hp_stopped = 0;
	/* 0 in the startup thread (runs before MINIT, which installs there itself); 1 for every later thread */
	if (hp_upg_want_install) {
		hp_uploadprogress_guard_globals->entry_installed = hp_upg_install_entry(HP_UPG_TSRMLS_C);
	}
}
static int hp_upg_detached = 0;
static int hp_upg_ini_forced = 0;
static int hp_upg_memlimit_forced = 0;
static int hp_upg_oom_hook_active = 0;
static int hp_upg_fix_probed = 0;
static int hp_upg_php_patched = 0;

/* ---- out-of-memory exit (see the header comment) ---- */
/* Fatal errors the engine raises from inside an allocation or a signal handler: the bailout they trigger
 * skips every cleanup between the raise point and the request's try block. (Timeouts only arrive this way
 * on 5.6/7.0; from 7.1 they are deferred to the VM and never interrupt request startup.) */
static int hp_upg_is_oom_message(const char *m)
{
	return m && (strstr(m, "Allowed memory size") != NULL || strstr(m, "Out of memory") != NULL
		|| strstr(m, "Maximum execution time") != NULL);
}

/* Unlink the upload temp files the parser registered so far. Runs inside the allocator's failure path, so
 * nothing here allocates; a file whose body was still being written is not registered yet and is left. */
static void hp_upg_unlink_uploads(void)
{
	HashTable *ht;
	HP_UPG_TSRMLS_FETCH();
	ht = SG(rfc1867_uploaded_files);
	if (!ht) {
		return;
	}
#if PHP_VERSION_ID < 70000
	{
		HashPosition pos;
		char *key;
		uint klen;
		ulong idx;
		zend_hash_internal_pointer_reset_ex(ht, &pos);
		while (zend_hash_get_current_key_ex(ht, &key, &klen, &idx, 0, &pos) == HASH_KEY_IS_STRING) {
			HP_UPG_UNLINK(key);
			zend_hash_move_forward_ex(ht, &pos);
		}
	}
#else
	{
		zend_string *key;
		ZEND_HASH_FOREACH_STR_KEY(ht, key) {
			if (key) {
				HP_UPG_UNLINK(ZSTR_VAL(key));
			}
		} ZEND_HASH_FOREACH_END();
	}
#endif
}

static void hp_upg_oom_exit(void)
{
	hp_upg_unlink_uploads();
	_exit(137);
}

#if PHP_VERSION_ID >= 80100
/* PHP 8.1+: zend_string* for both filename and message */
static void (*hp_upg_orig_error_cb)(int type, zend_string *error_filename, const uint32_t error_lineno, zend_string *message) = NULL;

static void hp_upg_error_cb(int type, zend_string *error_filename, const uint32_t error_lineno, zend_string *message)
{
	if (type == E_ERROR && EG(current_execute_data) == NULL && message && hp_upg_is_oom_message(ZSTR_VAL(message))) {
		hp_upg_oom_exit();
	}
	if (hp_upg_orig_error_cb) {
		hp_upg_orig_error_cb(type, error_filename, error_lineno, message);
	}
}
#elif PHP_VERSION_ID >= 80000
/* PHP 8.0: const char* filename, zend_string* message (filename became zend_string* in 8.1) */
static void (*hp_upg_orig_error_cb)(int type, const char *error_filename, const uint32_t error_lineno, zend_string *message) = NULL;

static void hp_upg_error_cb(int type, const char *error_filename, const uint32_t error_lineno, zend_string *message)
{
	if (type == E_ERROR && EG(current_execute_data) == NULL && message && hp_upg_is_oom_message(ZSTR_VAL(message))) {
		hp_upg_oom_exit();
	}
	if (hp_upg_orig_error_cb) {
		hp_upg_orig_error_cb(type, error_filename, error_lineno, message);
	}
}
#else
/* PHP 5.6 - 7.4: const char* filename + printf format/va_list (the format string carries the message text) */
static void (*hp_upg_orig_error_cb)(int type, const char *error_filename, const unsigned int error_lineno, const char *format, va_list args) = NULL;

static void hp_upg_error_cb(int type, const char *error_filename, const unsigned int error_lineno, const char *format, va_list args)
{
	HP_UPG_TSRMLS_FETCH();
	if (type == E_ERROR && EG(current_execute_data) == NULL && hp_upg_is_oom_message(format)) {
		hp_upg_oom_exit();
	}
	if (hp_upg_orig_error_cb) {
		hp_upg_orig_error_cb(type, error_filename, error_lineno, format, args);
	}
}
#endif

static void hp_upg_install_oom_hook(void)
{
	hp_upg_orig_error_cb = zend_error_cb;
	zend_error_cb = hp_upg_error_cb;
	hp_upg_oom_hook_active = 1;
}

static void hp_upg_remove_oom_hook(void)
{
	if (hp_upg_oom_hook_active && zend_error_cb == hp_upg_error_cb) {
		zend_error_cb = hp_upg_orig_error_cb;
	}
	hp_upg_oom_hook_active = 0;
	hp_upg_orig_error_cb = NULL;
}

/* ---- stale request state (see the header comment) ---- */
static int hp_upg_state_reset = 0;
static int (*hp_upg_orig_sapi_deactivate)(HP_UPG_TSRMLS_D) = NULL;
static int hp_upg_sapi_wrapped = 0;

#if PHP_VERSION_ID < 70000
#define HP_UPG_CLEAR_ZV(p) (p) = NULL          /* PHP 5: these globals are zval pointers */
#else
#define HP_UPG_CLEAR_ZV(zv) ZVAL_UNDEF(&(zv))
#endif

/* sapi_deactivate_module() frees the request_info strings and then calls the SAPI's deactivate callback
 * (same order on 5.6 - 8.5): clear the freed pointers here, as the fix does right after each efree(). */
static int hp_upg_sapi_deactivate(HP_UPG_TSRMLS_D)
{
	int r = SUCCESS;
	if (hp_upg_orig_sapi_deactivate) {
		r = hp_upg_orig_sapi_deactivate(HP_UPG_TSRMLS_C);
	}
	SG(request_info).auth_user = NULL;
	SG(request_info).auth_password = NULL;
	SG(request_info).auth_digest = NULL;
	SG(request_info).content_type_dup = NULL;
	SG(request_info).current_user = NULL;
	return r;
}

#if PHP_VERSION_ID >= 80100
/* OPcache stores a script right after compiling it, inside its own zend_compile_file hook; installed from
 * RINIT so this wrapper sits outside OPcache's and covers compile + store. */
static zend_op_array *(*hp_upg_orig_compile_file)(zend_file_handle *file_handle, int type) = NULL;
static int hp_upg_compile_hooked = 0;
static int hp_upg_compile_depth = 0;
static int hp_upg_limit_lifted = 0;

static void hp_upg_restore_limit(void)
{
	hp_upg_compile_depth = 0;
	if (hp_upg_limit_lifted) {
		hp_upg_limit_lifted = 0;
		if (PG(memory_limit) > 0) {
			/* fails only when the script already uses more than its limit; it then keeps running without one */
			zend_set_memory_limit((size_t) PG(memory_limit));
		}
	}
}

static zend_op_array *hp_upg_compile_file(zend_file_handle *file_handle, int type)
{
	zend_op_array *op_array;
	if (hp_upg_compile_depth++ == 0 && !hp_upg_limit_lifted && PG(memory_limit) > 0) {
		zend_set_memory_limit((size_t) -1);
		hp_upg_limit_lifted = 1;
	}
	op_array = hp_upg_orig_compile_file(file_handle, type);
	if (--hp_upg_compile_depth <= 0) {
		hp_upg_restore_limit();
	}
	return op_array;
}
#endif

#if PHP_VERSION_ID >= 80200
static int hp_upg_sxe_wanted;
static void hp_upg_sxe_hook(void);
#endif

static PHP_RINIT_FUNCTION(hp_uploadprogress_guard)
{
#if defined(ZTS) && PHP_VERSION_ID >= 70000
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
#if PHP_VERSION_ID >= 80100
	if (!hp_upg_compile_hooked && !hp_upg_php_patched && zend_get_extension("Zend OPcache")) {
		hp_upg_orig_compile_file = zend_compile_file;
		zend_compile_file = hp_upg_compile_file;
		hp_upg_compile_hooked = 1;
	}
	hp_upg_restore_limit();
#endif
#if PHP_VERSION_ID >= 80200
	if (hp_upg_sxe_wanted) {
		hp_upg_sxe_hook();
	}
#endif
	return SUCCESS;
}

/* Runs after zend_deactivate() destroyed the executor: everything below is already freed, only the stale
 * pointers are replaced by what init_executor() will set anyway, exactly as the fix does in shutdown. */
static ZEND_MODULE_POST_ZEND_DEACTIVATE_D(hp_uploadprogress_guard)
{
	int i;
	HP_UPG_TSRMLS_FETCH();
	if (hp_upg_php_patched) {
		return SUCCESS;
	}
#if PHP_VERSION_ID >= 80100
	hp_upg_restore_limit();
	EG(record_errors) = 0;
	EG(num_errors) = 0;
	EG(errors) = NULL;
#endif
#if PHP_VERSION_ID >= 80500
	HP_UPG_CLEAR_ZV(EG(last_fatal_error_backtrace));
#endif
	HP_UPG_CLEAR_ZV(EG(user_error_handler));
	HP_UPG_CLEAR_ZV(EG(user_exception_handler));
	memset(&EG(user_error_handlers_error_reporting), 0, sizeof(EG(user_error_handlers_error_reporting)));
	memset(&EG(user_error_handlers), 0, sizeof(EG(user_error_handlers)));
	memset(&EG(user_exception_handlers), 0, sizeof(EG(user_exception_handlers)));
	EG(error_handling) = EH_NORMAL;
	EG(exception) = NULL;
	EG(objects_store).object_buckets = NULL;
	EG(objects_store).top = 1;
	for (i = 0; i < (int) (sizeof(PG(http_globals)) / sizeof(PG(http_globals)[0])); i++) {
		HP_UPG_CLEAR_ZV(PG(http_globals)[i]);
	}
	PG(modules_activated) = 0;
	hp_upg_state_reset = 1;
	return SUCCESS;
}

/* ---- Force memory_limit = -1 (CVE-2026-109618 OOM prevention) ----
 * Same technique as hp_upg_force_ini_off(): write the MASTER ini value and lock to PHP_INI_SYSTEM.
 * With memory_limit=-1 the allocator never fires the OOM bailout/longjmp, so the corruption that
 * CVE-2026-109618 exploits cannot happen. The process is bounded only by the OS cgroup MemoryMax. */
static void hp_upg_force_memory_unlimited(void)
{
	const char name[] = "memory_limit";
	zend_ini_entry *e;
	HP_UPG_TSRMLS_FETCH();
#if PHP_VERSION_ID < 70000
	if (zend_hash_find(EG(ini_directives), (char *) name, sizeof(name), (void **) &e) != SUCCESS) {
		return;
	}
	if (e->on_modify) {
		e->on_modify(e, "-1", 2, e->mh_arg1, e->mh_arg2, e->mh_arg3, ZEND_INI_STAGE_ACTIVATE TSRMLS_CC);
	}
	e->value = zend_strndup("-1", 2);
	e->value_length = 2;
#else
	e = zend_hash_str_find_ptr(EG(ini_directives), name, sizeof(name) - 1);
	if (!e) {
		return;
	}
	{
		zend_string *neg1 = zend_string_init("-1", 2, 1);
		if (e->on_modify) {
			e->on_modify(e, neg1, e->mh_arg1, e->mh_arg2, e->mh_arg3, ZEND_INI_STAGE_ACTIVATE);
		}
		if (e->value) {
#if PHP_VERSION_ID < 70300
			zend_string_release(e->value);
#else
			zend_string_release_ex(e->value, 1);
#endif
		}
		e->value = neg1;
	}
#endif
	e->modifiable = PHP_INI_SYSTEM;
	hp_upg_memlimit_forced = 1;
}

/* Make the switch visible: set the MASTER value of session.upload_progress.enabled to 0 and lock the entry
 * to PHP_INI_SYSTEM, so ini_get()/phpinfo() report it Off and .user.ini / .htaccess / ini_set() cannot turn
 * it back on. The master value is written directly (not via zend_alter_ini_entry, which PHP would restore
 * at the end of the first request). Runs at MINIT after ext/session registered the entry. */
static void hp_upg_force_ini_off(void)
{
	const char name[] = "session.upload_progress.enabled";
	zend_ini_entry *e;
	HP_UPG_TSRMLS_FETCH();
#if PHP_VERSION_ID < 70000
	if (zend_hash_find(EG(ini_directives), (char *) name, sizeof(name), (void **) &e) != SUCCESS) {
		return;
	}
	if (e->on_modify) {
		e->on_modify(e, "0", 1, e->mh_arg1, e->mh_arg2, e->mh_arg3, ZEND_INI_STAGE_STARTUP TSRMLS_CC);
	}
	/* PHP 5: the default value is a static literal, a configured one a strdup; neither is ours to free.
	 * Overwrite the pointer (one tiny persistent string per process). */
	e->value = zend_strndup("0", 1);
	e->value_length = 1;
#else
	e = zend_hash_str_find_ptr(EG(ini_directives), name, sizeof(name) - 1);
	if (!e) {
		return;
	}
	{
		zend_string *zero = zend_string_init("0", 1, 1);
		if (e->on_modify) {
			e->on_modify(e, zero, e->mh_arg1, e->mh_arg2, e->mh_arg3, ZEND_INI_STAGE_STARTUP);
		}
		if (e->value) {
#if PHP_VERSION_ID < 70300
			zend_string_release(e->value);   /* zend_string_release_ex() exists from PHP 7.3 */
#else
			zend_string_release_ex(e->value, 1);
#endif
		}
		e->value = zero;
	}
#endif
	e->modifiable = PHP_INI_SYSTEM;
	hp_upg_ini_forced = 1;
}
static int hp_upg_mbstring = 0;
#if PHP_VERSION_ID < 70000
#define HP_UPG_MODULE_LOADED(name) zend_hash_exists(&module_registry, name, sizeof(name))
#else
#define HP_UPG_MODULE_LOADED(name) zend_hash_str_exists(&module_registry, name, sizeof(name) - 1)
#endif
static char hp_upg_php_version[32] = "";

/* First PHP release of each branch that contains the official fix; any branch newer than the last entry
 * was released with it. Older branches keep their version number when a vendor backports the fix, so they
 * are never reported as patched here (mode=parse then keeps the carried fixed parser, which is harmless on
 * a patched build). */
static const struct { const char *branch; const char *fixed; } hp_upg_fixed[] = {
	{ "8.6.", "8.6.0" }, { "8.5.", "8.5.12" }, { "8.4.", "8.4.27" }, { "8.3.", "8.3.36" }, { "8.2.", "8.2.35" }, { NULL, NULL }
};

static void hp_upg_detect_patched(void)
{
	zval *v;
	size_t i;
	int major = 0, minor = 0;
#if PHP_VERSION_ID < 70000
	zval **vv;
#endif
	HP_UPG_TSRMLS_FETCH();
	/* Engines carrying the fix export a symbol the old ones lack, whatever version number a vendor backport
	 * keeps: zend_handle_delayed_oom (8.2+ delayed out-of-memory) or zend_mm_safe_error_ex (7.4/8.0/8.1
	 * "minimal mitigation": the allocator _exit()s instead of bailing out). */
	if (hp_upg_sym_delayed_oom != NULL || hp_upg_sym_safe_error_ex != NULL) {
		hp_upg_php_patched = 1;
		hp_upg_fix_probed = 1;
	}
#if PHP_VERSION_ID < 70000
	if (zend_hash_find(EG(zend_constants), "PHP_VERSION", sizeof("PHP_VERSION"), (void **) &vv) == SUCCESS) {
		zend_constant *c = (zend_constant *) *vv;
		v = &c->value;
	} else {
		return;
	}
#else
	v = zend_get_constant_str("PHP_VERSION", sizeof("PHP_VERSION") - 1);
	if (!v) {
		return;
	}
#endif
	if (Z_TYPE_P(v) != IS_STRING) {
		return;
	}
	strncpy(hp_upg_php_version, Z_STRVAL_P(v), sizeof(hp_upg_php_version) - 1);
	for (i = 0; hp_upg_fixed[i].branch; i++) {
		if (strncmp(hp_upg_php_version, hp_upg_fixed[i].branch, strlen(hp_upg_fixed[i].branch)) == 0) {
			if (php_version_compare(hp_upg_php_version, hp_upg_fixed[i].fixed) >= 0) {
				hp_upg_php_patched = 1;
			}
			return;
		}
	}
	{
		/* no sscanf/strtol: on glibc >= 2.38 they bind to GLIBC_2.38 symbols and the .so stops loading on older hosts */
		const char *p = hp_upg_php_version;
		while (*p >= '0' && *p <= '9') major = major * 10 + (*p++ - '0');
		if (*p == '.') {
			p++;
			while (*p >= '0' && *p <= '9') minor = minor * 10 + (*p++ - '0');
		}
	}
	if (major > 8 || (major == 8 && minor > 6)) {
		hp_upg_php_patched = 1;
	}
}

/* mbstring.encoding_translation=On: only PHP's own parser has mbstring's hooks, see the header comment. */
static int hp_upg_native_needed(void)
{
	return hp_upg_mbstring && INI_INT("mbstring.encoding_translation");
}

/* ---- unserialize() re-entrancy isolation ----
 * unserialize() and session_decode() share the context of an outer unserialization when one is active
 * (BG(unserialize).level > 0 and serialize_lock 0). PHP relies on that for one thing only: a
 * Serializable::unserialize() method the engine calls while parsing, whose own unserialize() must see the
 * outer back-references. var_destroy() frees the back-reference chunks first and then drops the dtor-list
 * entries, __wakeup()'s return value and __unserialize()'s argument without holding serialize_lock, so a
 * destructor that runs there and calls unserialize() reuses freed memory (use-after-free). Every nested
 * call that is not that Serializable path, or that has a destructor or generator between it and the outer
 * call, is run here as a top-level call: own context, outer context restored afterwards (also on bailout). */
#if PHP_VERSION_ID >= 70200
typedef zif_handler hp_upg_handler_t;
#else
typedef void (*hp_upg_handler_t)(INTERNAL_FUNCTION_PARAMETERS);
#endif
#if PHP_VERSION_ID < 70000
#define HP_UPG_UNSER_DATA var_hash
#else
#define HP_UPG_UNSER_DATA data
#endif

static zend_function *hp_upg_unser_fn = NULL;
static zend_function *hp_upg_sdecode_fn = NULL;
static hp_upg_handler_t hp_upg_orig_unser = NULL;
static hp_upg_handler_t hp_upg_orig_sdecode = NULL;
static int hp_upg_unser_hooked = 0;

static int hp_upg_name_is(const char *n, size_t len, const char *lit, size_t litlen)
{
	return n && len == litlen && zend_binary_strcasecmp(n, len, lit, litlen) == 0;
}

static int hp_upg_is_origin(zend_function *f)
{
	return f && ((hp_upg_unser_fn && f == hp_upg_unser_fn) || (hp_upg_sdecode_fn && f == hp_upg_sdecode_fn));
}

#if PHP_VERSION_ID >= 70000
static int hp_upg_nested_may_share(zend_execute_data *self)
{
	zend_execute_data *ex = self ? self->prev_execute_data : NULL;
	int saw_serializable = 0;
	for (; ex; ex = ex->prev_execute_data) {
		zend_function *f = ex->func;
		if (!f) {
			continue;
		}
		if (f->type == ZEND_INTERNAL_FUNCTION) {
			if (hp_upg_is_origin(f)) {
				break; /* the call that opened the outer context */
			}
			continue;
		}
		if (f->common.fn_flags & ZEND_ACC_GENERATOR) {
			return 0;
		}
		if (f->common.scope && f->common.function_name) {
			const char *n = ZSTR_VAL(f->common.function_name);
			size_t len = ZSTR_LEN(f->common.function_name);
			if (hp_upg_name_is(n, len, "__destruct", sizeof("__destruct") - 1)) {
				return 0;
			}
			if (hp_upg_name_is(n, len, "unserialize", sizeof("unserialize") - 1)
					&& instanceof_function(f->common.scope, zend_ce_serializable)) {
				saw_serializable = 1;
			}
		}
	}
	return saw_serializable;
}
#define HP_UPG_MAY_SHARE() hp_upg_nested_may_share(execute_data)
#else
/* PHP 5: internal calls have no frame of their own; a frame's function_state.function is the function it is
 * calling. Frames zend_call_function() inserts have no op_array. */
static int hp_upg_nested_may_share(TSRMLS_D)
{
	zend_execute_data *ex = EG(current_execute_data);
	int first = 1, saw_serializable = 0;
	for (; ex; ex = ex->prev_execute_data, first = 0) {
		zend_op_array *op = ex->op_array;
		if (!first && hp_upg_is_origin(ex->function_state.function)) {
			break;
		}
		if (!op) {
			continue;
		}
#ifdef ZEND_ACC_GENERATOR
		if (op->fn_flags & ZEND_ACC_GENERATOR) {
			return 0;
		}
#endif
		if (op->scope && op->function_name) {
			size_t len = strlen(op->function_name);
			if (hp_upg_name_is(op->function_name, len, "__destruct", sizeof("__destruct") - 1)) {
				return 0;
			}
			if (hp_upg_name_is(op->function_name, len, "unserialize", sizeof("unserialize") - 1)
					&& instanceof_function(op->scope, zend_ce_serializable TSRMLS_CC)) {
				saw_serializable = 1;
			}
		}
	}
	return saw_serializable;
}
#define HP_UPG_MAY_SHARE() hp_upg_nested_may_share(TSRMLS_C)
#endif

static void hp_upg_run_isolated(hp_upg_handler_t orig, INTERNAL_FUNCTION_PARAMETERS)
{
	unsigned saved_level = BG(unserialize).level;
	void *saved_data = (void *) BG(unserialize).HP_UPG_UNSER_DATA;

	BG(unserialize).level = 0;
	BG(unserialize).HP_UPG_UNSER_DATA = NULL;
	zend_try {
		orig(INTERNAL_FUNCTION_PARAM_PASSTHRU);
	} zend_catch {
		BG(unserialize).level = saved_level;
		BG(unserialize).HP_UPG_UNSER_DATA = saved_data;
		zend_bailout();
	} zend_end_try();
	BG(unserialize).level = saved_level;
	BG(unserialize).HP_UPG_UNSER_DATA = saved_data;
}

#define HP_UPG_NEEDS_ISOLATION() (BG(unserialize).level && !BG(serialize_lock) && !HP_UPG_MAY_SHARE())

static ZEND_NAMED_FUNCTION(hp_upg_unserialize)
{
	if (HP_UPG_NEEDS_ISOLATION()) {
		hp_upg_run_isolated(hp_upg_orig_unser, INTERNAL_FUNCTION_PARAM_PASSTHRU);
		return;
	}
	hp_upg_orig_unser(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static ZEND_NAMED_FUNCTION(hp_upg_session_decode)
{
	if (HP_UPG_NEEDS_ISOLATION()) {
		hp_upg_run_isolated(hp_upg_orig_sdecode, INTERNAL_FUNCTION_PARAM_PASSTHRU);
		return;
	}
	hp_upg_orig_sdecode(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

#if PHP_VERSION_ID < 70000
static zend_function *hp_upg_find_function(const char *name, size_t len TSRMLS_DC)
{
	zend_function *f;
	if (zend_hash_find(CG(function_table), (char *) name, len + 1, (void **) &f) == SUCCESS) {
		return f;
	}
	return NULL;
}
#define HP_UPG_FIND(name) hp_upg_find_function(name, sizeof(name) - 1 TSRMLS_CC)
#else
#define HP_UPG_FIND(name) ((zend_function *) zend_hash_str_find_ptr(CG(function_table), name, sizeof(name) - 1))
#endif

static void hp_upg_hook_unserialize(HP_UPG_TSRMLS_D)
{
	zend_function *f = HP_UPG_FIND("unserialize");
	if (!f || f->type != ZEND_INTERNAL_FUNCTION) {
		return;
	}
	hp_upg_unser_fn = f;
	hp_upg_orig_unser = f->internal_function.handler;
	f->internal_function.handler = hp_upg_unserialize;
	f = HP_UPG_FIND("session_decode");
	if (f && f->type == ZEND_INTERNAL_FUNCTION) {
		hp_upg_sdecode_fn = f;
		hp_upg_orig_sdecode = f->internal_function.handler;
		f->internal_function.handler = hp_upg_session_decode;
	}
	hp_upg_unser_hooked = 1;
}

static void hp_upg_unhook_unserialize(void)
{
	if (hp_upg_unser_fn && hp_upg_unser_fn->internal_function.handler == hp_upg_unserialize) {
		hp_upg_unser_fn->internal_function.handler = hp_upg_orig_unser;
	}
	if (hp_upg_sdecode_fn && hp_upg_sdecode_fn->internal_function.handler == hp_upg_session_decode) {
		hp_upg_sdecode_fn->internal_function.handler = hp_upg_orig_sdecode;
	}
	hp_upg_unser_fn = hp_upg_sdecode_fn = NULL;
	hp_upg_unser_hooked = 0;
}

/* ---- SimpleXML GC double free (php-src#24488) ----
 * The fixed releases add the table an object's get_gc returns to the GC buffer. SimpleXML's get_gc returns
 * its own properties table, and sxe_object_free_storage() frees that table with zend_hash_release(), which
 * does not take it out of the buffer: the GC then frees it a second time. The upstream fix releases it with
 * zend_array_release() instead. Here SimpleXML's free_obj handler is wrapped to do exactly that: the table is
 * taken off the object, SimpleXML frees the rest (finding nothing to release), and the table is released with
 * zend_array_release(). php_sxe_object starts with node, document, properties (all pointers) and the handler
 * table's offset is that of the embedded zend_object. Installed on the first request (objects cannot be
 * created at startup), on the affected releases only; harmless once the upstream fix is in. */
#if PHP_VERSION_ID >= 80200
static zend_object_handlers *hp_upg_sxe_handlers = NULL;
static void (*hp_upg_sxe_orig_free)(zend_object *object) = NULL;
static int hp_upg_sxe_wanted = 0;
static int hp_upg_sxe_hooked = 0;
#ifdef ZTS
static volatile long hp_upg_sxe_once = 0; /* threads may enter RINIT together: only one may install the hook */
#endif

static void hp_upg_sxe_free_obj(zend_object *object)
{
	HashTable **slot = (HashTable **) ((char *) object - object->handlers->offset + 2 * sizeof(void *));
	HashTable *props = *slot;

	*slot = NULL;
	hp_upg_sxe_orig_free(object);
	if (props) {
		zend_array_release(props);
	}
}

static void hp_upg_sxe_hook(void)
{
	zend_class_entry *ce = zend_hash_str_find_ptr(CG(class_table), "simplexmlelement", sizeof("simplexmlelement") - 1);
	zend_object *probe;

#ifdef ZTS
#ifdef _MSC_VER
	if (InterlockedExchange((volatile LONG *) &hp_upg_sxe_once, 1)) {
		return;
	}
#else
	if (__sync_lock_test_and_set(&hp_upg_sxe_once, 1)) {
		return;
	}
#endif
#endif
	hp_upg_sxe_wanted = 0; /* one attempt per process */
	if (!ce || !ce->create_object) {
		return;
	}
	probe = ce->create_object(ce);
	if (!probe) {
		return;
	}
	hp_upg_sxe_handlers = (zend_object_handlers *) probe->handlers;
	OBJ_RELEASE(probe);
	if (!hp_upg_sxe_handlers || !hp_upg_sxe_handlers->free_obj || hp_upg_sxe_handlers->offset < (int) (3 * sizeof(void *))) {
		hp_upg_sxe_handlers = NULL;
		return;
	}
	hp_upg_sxe_orig_free = hp_upg_sxe_handlers->free_obj;
	hp_upg_sxe_handlers->free_obj = hp_upg_sxe_free_obj;
	hp_upg_sxe_hooked = 1;
}

static void hp_upg_sxe_unhook(void)
{
	if (hp_upg_sxe_hooked && hp_upg_sxe_handlers && hp_upg_sxe_handlers->free_obj == hp_upg_sxe_free_obj) {
		hp_upg_sxe_handlers->free_obj = hp_upg_sxe_orig_free;
	}
	hp_upg_sxe_hooked = 0;
}
#endif

#if PHP_VERSION_ID >= 80200
/* Releases carrying the GC change of GH-24050 (php-src#24488): 8.4.27 and 8.5.12 onward until fixed. */
static int hp_upg_sxe_affected(void)
{
	if (strncmp(hp_upg_php_version, "8.4.", 4) == 0) {
		return php_version_compare(hp_upg_php_version, "8.4.27") >= 0;
	}
	if (strncmp(hp_upg_php_version, "8.5.", 4) == 0) {
		return php_version_compare(hp_upg_php_version, "8.5.12") >= 0;
	}
	return 0;
}
#endif

PHP_INI_BEGIN()
	PHP_INI_ENTRY("hp_uploadprogress_guard.mode", "parse", PHP_INI_SYSTEM, NULL)
	PHP_INI_ENTRY("hp_uploadprogress_guard.allow_ips", "", PHP_INI_SYSTEM, NULL)
	PHP_INI_ENTRY("hp_uploadprogress_guard.detach_upload_progress", "1", PHP_INI_SYSTEM, NULL)
	PHP_INI_ENTRY("hp_uploadprogress_guard.force_unlimited_memory", "0", PHP_INI_SYSTEM, NULL)
	PHP_INI_ENTRY("hp_uploadprogress_guard.unserialize_isolation", "1", PHP_INI_SYSTEM, NULL)
	PHP_INI_ENTRY("hp_uploadprogress_guard.simplexml_gc_fix", "1", PHP_INI_SYSTEM, NULL)
PHP_INI_END()

static int hp_upg_client_allowed(void)
{
	const char *allow = INI_STR("hp_uploadprogress_guard.allow_ips");
	char *ip;
	int allowed = 0;
	HP_UPG_TSRMLS_FETCH();

	if (!allow || !*allow) {
		return 0;
	}
#if PHP_VERSION_ID < 70000
	ip = sapi_getenv("REMOTE_ADDR", sizeof("REMOTE_ADDR") - 1 TSRMLS_CC);
#else
	ip = sapi_getenv("REMOTE_ADDR", sizeof("REMOTE_ADDR") - 1);
#endif
	if (ip && *ip) {
		size_t iplen = strlen(ip);
		const char *p = allow;
		while (*p) {
			const char *q;
			while (*p == ' ' || *p == ',') p++;
			q = p;
			while (*q && *q != ',' && *q != ' ') q++;
			if ((size_t)(q - p) == iplen && memcmp(p, ip, iplen) == 0) {
				allowed = 1;
				break;
			}
			p = q;
		}
	}
	if (ip) {
		efree(ip);
	}
	return allowed;
}

static SAPI_POST_HANDLER_FUNC(hp_upg_dispatch)
{
	const char *mode = INI_STR("hp_uploadprogress_guard.mode");

	if (mode && strcasecmp(mode, "block") == 0 && !hp_upg_client_allowed()) {
		/* Nothing is read from the body; the SAPI discards it. */
		SG(sapi_headers).http_response_code = 415;
		/* error log only: never the output stream, whatever display_errors says */
#if PHP_VERSION_ID < 70000
		php_log_err("hp_uploadprogress_guard: multipart/form-data request refused (mode=block)" TSRMLS_CC);
#else
		php_log_err("hp_uploadprogress_guard: multipart/form-data request refused (mode=block)");
#endif
		return;
	}
#if PHP_VERSION_ID < 70000
	if (hp_upg_native_needed()) {
		rfc1867_post_handler(content_type_dup, arg TSRMLS_CC);
		return;
	}
	hp_rfc1867_post_handler(content_type_dup, arg TSRMLS_CC);
#else
	if (hp_upg_native_needed()) {
		rfc1867_post_handler(content_type_dup, arg);
		return;
	}
	hp_rfc1867_post_handler(content_type_dup, arg);
#endif
}

static PHP_MINIT_FUNCTION(hp_uploadprogress_guard)
{
#if defined(ZTS) && PHP_VERSION_ID >= 70000
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	REGISTER_INI_ENTRIES();
	hp_upg_detect_patched();
#ifdef HP_UPG_TEST_FORCE_PARSE
	hp_upg_php_patched = 0; /* test builds only: exercise the carried parser on a patched engine */
#endif
	hp_upg_mbstring = HP_UPG_MODULE_LOADED("mbstring");
	{
		const char *mode = INI_STR("hp_uploadprogress_guard.mode");
		/* native: never replace. parse on a PHP that already carries the fix: step aside too. */
		if (!((mode && strcasecmp(mode, "native") == 0) || (hp_upg_php_patched && !(mode && strcasecmp(mode, "block") == 0)))) {
			hp_upg_want_install = 1;
			HP_UPG_G(entry_installed) = hp_upg_install_entry(HP_UPG_TSRMLS_C);
		}
	}
	if (INI_BOOL("hp_uploadprogress_guard.detach_upload_progress")) {
		if (php_rfc1867_callback != NULL) {
			php_rfc1867_callback = NULL;
			hp_upg_detached = 1;
		} else if (HP_UPG_MODULE_LOADED("session")) {
			/* ext/session starts before this module (declared dependency) and installs its callback in its
			 * MINIT: if it is gone, an extension loaded earlier cleared it. Same state, same ini lock. */
			hp_upg_detached = 2;
		}
	}
	if (hp_upg_detached) {
		hp_upg_force_ini_off();
	}
	if (!hp_upg_php_patched) {
		hp_upg_install_oom_hook();
		hp_upg_orig_sapi_deactivate = sapi_module.deactivate;
		sapi_module.deactivate = hp_upg_sapi_deactivate;
		hp_upg_sapi_wrapped = 1;
	}
	if (INI_BOOL("hp_uploadprogress_guard.force_unlimited_memory")) {
		hp_upg_force_memory_unlimited();
	}
	if (INI_BOOL("hp_uploadprogress_guard.unserialize_isolation")) {
		hp_upg_hook_unserialize(HP_UPG_TSRMLS_C);
	}
#if PHP_VERSION_ID >= 80200
	if (INI_BOOL("hp_uploadprogress_guard.simplexml_gc_fix") && hp_upg_sxe_affected()) {
		hp_upg_sxe_wanted = 1;
	}
#endif
	return SUCCESS;
}

static PHP_MSHUTDOWN_FUNCTION(hp_uploadprogress_guard)
{
	hp_upg_unhook_unserialize();
#if PHP_VERSION_ID >= 80200
	hp_upg_sxe_unhook();
#endif
	hp_upg_remove_oom_hook();
	if (hp_upg_sapi_wrapped && sapi_module.deactivate == hp_upg_sapi_deactivate) {
		sapi_module.deactivate = hp_upg_orig_sapi_deactivate;
	}
	hp_upg_sapi_wrapped = 0;
#if PHP_VERSION_ID >= 80100
	if (hp_upg_compile_hooked && zend_compile_file == hp_upg_compile_file) {
		zend_compile_file = hp_upg_orig_compile_file;
	}
	hp_upg_compile_hooked = 0;
#endif
	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}

static PHP_MINFO_FUNCTION(hp_uploadprogress_guard)
{
	int live;
	php_info_print_table_start();
	php_info_print_table_row(2, HP_MPG_NAME, "enabled");
	php_info_print_table_row(2, "version", HP_MPG_VERSION);
	live = hp_upg_entry_live(HP_UPG_TSRMLS_C);
	php_info_print_table_row(2, "multipart/form-data handler replaced", live ? "yes"
		: (hp_upg_want_install ? "no (another extension installed its own handler in this thread, see README)" : "no"));
	php_info_print_table_row(2, "mode", INI_STR("hp_uploadprogress_guard.mode"));
	php_info_print_table_row(2, "parser memory-headroom guard", live ? (PG(memory_limit) > 0 ? "yes" : "not needed (memory_limit unlimited)") : "no (parser not replaced)");
	/* the setting is PHP_INI_PERDIR: read it now, as the request path does (hp_upg_native_needed) */
	php_info_print_table_row(2, "mbstring.encoding_translation requests", live ? (hp_upg_mbstring
		? (INI_INT("mbstring.encoding_translation") ? "handed to PHP's parser (mbstring.encoding_translation is On)" : "module's parser (mbstring.encoding_translation is Off)")
		: "n/a (mbstring not loaded)") : "n/a");
	php_info_print_table_row(2, "running PHP already carries the official fix", hp_upg_php_patched
		? (hp_upg_fix_probed
			? (live ? "yes (fix symbol exported by the engine)" : "yes (fix symbol exported by the engine; parser replacement skipped)")
			: (live ? "yes" : "yes (parser replacement skipped)"))
		: "no");
	php_info_print_table_row(2, "session.upload_progress handler detached", hp_upg_detached == 1 ? "yes"
		: (hp_upg_detached == 2 ? "yes (already cleared by an extension loaded earlier)" : "no"));
	php_info_print_table_row(2, "session.upload_progress.enabled forced to 0 and locked (PHP_INI_SYSTEM)", hp_upg_ini_forced ? "yes" : "no");
	php_info_print_table_row(2, "out-of-memory exit (_exit(137) while no script is executing)", hp_upg_oom_hook_active ? "active" : (hp_upg_php_patched ? "not needed (engine carries the fix)" : "inactive"));
	php_info_print_table_row(2, "stale request state cleared at request end (handlers, superglobals, request_info)", hp_upg_php_patched ? "not needed (engine carries the fix)" : (hp_upg_sapi_wrapped ? "active" : "inactive"));
#if PHP_VERSION_ID >= 80100
	php_info_print_table_row(2, "memory_limit lifted while OPcache compiles and stores a script", hp_upg_php_patched ? "not needed (engine carries the fix)" : (hp_upg_compile_hooked ? "active" : (zend_get_extension("Zend OPcache") ? "pending (installed on first request)" : "n/a (OPcache not loaded)")));
#endif
	{
		char eff[160];
		const char *row = "no";
		if (hp_upg_memlimit_forced) {
			if (PG(memory_limit) > 0) {
				snprintf(eff, sizeof(eff), "NO: overridden after startup, effective memory_limit is %lld bytes (php-fpm pool php_value/php_admin_value or PHP_ADMIN_VALUE)", (long long) PG(memory_limit));
				row = eff;
			} else {
				row = "yes";
			}
		}
		php_info_print_table_row(2, "memory_limit forced to -1 (unlimited) and locked", row);
	}
#if PHP_VERSION_ID >= 80200
	php_info_print_table_row(2, "SimpleXML GC double-free workaround (php-src#24488)", hp_upg_sxe_hooked ? "active"
		: (hp_upg_sxe_wanted ? "pending (installed on first request)"
		: (hp_upg_sxe_affected() ? (INI_BOOL("hp_uploadprogress_guard.simplexml_gc_fix") ? "n/a (SimpleXML not loaded)" : "off") : "not needed (this PHP release)")));
#endif
	php_info_print_table_row(2, "unserialize() re-entrancy isolation (destructors during var_destroy)", hp_upg_unser_hooked ? (hp_upg_sdecode_fn ? "active (unserialize, session_decode)" : "active (unserialize)") : "off");
	php_info_print_table_end();
	DISPLAY_INI_ENTRIES();
}

static const zend_module_dep hp_upg_deps[] = {
	ZEND_MOD_OPTIONAL("session")
	ZEND_MOD_OPTIONAL("mbstring")
	ZEND_MOD_END
};

zend_module_entry hp_uploadprogress_guard_module_entry = {
	STANDARD_MODULE_HEADER_EX,
	NULL,
	hp_upg_deps,
	HP_MPG_NAME,
	NULL,
	PHP_MINIT(hp_uploadprogress_guard),
	PHP_MSHUTDOWN(hp_uploadprogress_guard),
	PHP_RINIT(hp_uploadprogress_guard),
	NULL,
	PHP_MINFO(hp_uploadprogress_guard),
	HP_MPG_VERSION,
	PHP_MODULE_GLOBALS(hp_uploadprogress_guard),
	PHP_GINIT(hp_uploadprogress_guard),
	NULL,
	ZEND_MODULE_POST_ZEND_DEACTIVATE_N(hp_uploadprogress_guard),
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_HP_UPLOADPROGRESS_GUARD
ZEND_GET_MODULE(hp_uploadprogress_guard)
#endif
