// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

namespace zeek
	{

/**
 * Set the process affinity to a given CPU.  Currently only supported on
 * Linux and FreeBSD.
 * @param core_number  the core to which this process should set its affinity.
 * Cores are typically numbered 0..N.
 * @return true if the affinity is successfully set and false if not with
 * errno additionally being set to indicate the reason.
 */
bool set_affinity(int core_number);

	} // namespace zeek
