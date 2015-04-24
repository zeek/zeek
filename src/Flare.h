// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BRO_FLARE_H
#define BRO_FLARE_H

#include "Pipe.h"

namespace bro {

class Flare {
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
		{ return pipe.ReadFD(); }

	/**
	 * Put the object in the "ready" state.
	 */
	void Fire();

	/**
	 * Take the object out of the "ready" state.
	 */
	void Extinguish();

private:
	Pipe pipe;
};

} // namespace bro

#endif // BRO_FLARE_H
