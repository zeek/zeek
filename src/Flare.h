// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#ifndef _MSC_VER
#include "Pipe.h"
#endif

namespace zeek::detail
	{

class Flare
	{
public:
	/**
	 * Create a flare object that can be used to signal a "ready" status via
	 * a file descriptor that may be integrated with select(), poll(), etc.
	 * Not thread-safe, but that should only require Fire()/Extinguish() calls
	 * to be made mutually exclusive (across all copies of a Flare).
	 */
	Flare();

	/**
	 * @return a file descriptor that will become ready if the flare has been
	 *         Fire()'d and not yet Extinguished()'d.
	 */
	int FD() const
#ifndef _MSC_VER
		{
		return pipe.ReadFD();
		}
#else
		{
		return recvfd;
		}
#endif

	/**
	 * Put the object in the "ready" state.
	 * @param signal_safe  whether to skip error-reporting functionality that
	 * is not async-signal-safe (errors still abort the process regardless)
	 */
	void Fire(bool signal_safe = false);

	/**
	 * Take the object out of the "ready" state.
	 * @param signal_safe  whether to skip error-reporting functionality that
	 * is not async-signal-safe (errors still abort the process regardless)
	 * @return number of bytes read from the pipe, corresponds to the number
	 * of times Fire() was called.
	 */
	int Extinguish(bool signal_safe = false);

private:
#ifndef _MSC_VER
	Pipe pipe;
#else
	int sendfd, recvfd;
#endif
	};

	} // namespace zeek::detail
