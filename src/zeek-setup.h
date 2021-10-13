// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Options.h"

namespace zeek::detail
	{

struct SetupResult
	{
	int code = 0;
	Options options;
	};

/**
 * Initializes Zeek's global state.
 * @param argc  the argument count (same semantics as main function)
 * @param argv  the argument strings (same semantics as main function)
 * @param options  if provided, those options are used instead of
 * deriving them by parsing the "argv" list.  The "argv" list still
 * needs to be provided regardless since some functionality requires
 * it, particularly, several things use the value of argv[0].
 */
SetupResult setup(int argc, char** argv, Options* options = nullptr);

/**
 * Cleans up Zeek's global state.
 * @param did_run_loop  whether the run_loop() function was called.
 */
int cleanup(bool did_run_loop);

	} // namespace zeek::detail
