/* Proposed shared header: source-reviewed, not build-tested. */
#ifndef HP_UPLOADPROGRESS_GUARD_H
#define HP_UPLOADPROGRESS_GUARD_H

#include "php.h"

/* The SAPI's table of POST handlers lives in per-thread SAPI globals: on a thread-safe build every new thread
 * starts from PHP's default entries (sapi_globals_ctor), so a handler registered at MINIT exists in the
 * startup thread only; Apache's request threads (mpm_winnt, worker, event) would keep PHP's own parser. The
 * entry is therefore installed per thread, from the module-globals constructor, which the engine runs in
 * every new thread before its first request. The status rows read the live table, never a flag. */
ZEND_BEGIN_MODULE_GLOBALS(hp_uploadprogress_guard)
	int entry_installed;
	int hp_stopped;
ZEND_END_MODULE_GLOBALS(hp_uploadprogress_guard)

ZEND_EXTERN_MODULE_GLOBALS(hp_uploadprogress_guard)

/*
 * Deliberately use the ordinary TSRMG accessor for the parser.
 * PHP 5 ZTS: the existing parser functions carry TSRMLS context.
 * PHP 7+ ZTS: TSRMG obtains the current thread context itself.
 * This accessor does not depend on this extension's static TSRMLS cache.
 * Keep the existing HP_UPG_G accessor in the main C file unchanged.
 */
#ifdef ZTS
# define HP_UPG_PARSER_G(v) \
	TSRMG(hp_uploadprogress_guard_globals_id, zend_hp_uploadprogress_guard_globals *, v)
#else
# define HP_UPG_PARSER_G(v) (hp_uploadprogress_guard_globals.v)
#endif

#endif /* HP_UPLOADPROGRESS_GUARD_H */
