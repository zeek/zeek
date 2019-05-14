/*
 * See the file "COPYING" in the main distribution directory for copyright.
 */

#include "zeek-config.h"			/* must appear before first ifdef */

#include <sys/types.h>

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <signal.h>
#ifdef HAVE_SIGACTION
#include <string.h>
#endif

#include "setsignal.h"

/*
 * An os independent signal() with BSD semantics, e.g. the signal
 * catcher is restored following service of the signal.
 *
 * When sigset() is available, signal() has SYSV semantics and sigset()
 * has BSD semantics and call interface. Unfortunately, Linux does not
 * have sigset() so we use the more complicated sigaction() interface
 * there.
 *
 * Did I mention that signals suck?
 */
RETSIGTYPE
(*setsignal (int sig, RETSIGTYPE (*func)(int)))(int)
{
#ifdef HAVE_SIGACTION
	struct sigaction old, new;

	memset(&new, 0, sizeof(new));
	new.sa_handler = func;
#ifdef SA_RESTART
	new.sa_flags |= SA_RESTART;
#endif
	if (sigaction(sig, &new, &old) < 0)
		return (SIG_ERR);
	return (old.sa_handler);

#else
#ifdef HAVE_SIGSET
	return (sigset(sig, func));
#else
	return (signal(sig, func));
#endif
#endif
}

