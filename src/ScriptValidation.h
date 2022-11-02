// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

namespace zeek::detail
	{

/**
 * Run extra validations on the parsed AST after everything is initialized
 * and report any errors via zeek::reporter->Error().
 */
void script_validation();
	}
