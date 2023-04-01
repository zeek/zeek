// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

namespace zeek::detail
	{

class Stmt;

/**
 * Run extra validations on the parsed AST after everything is initialized
 * and report any errors via deprecation warnings or zeek::reporter->Error().
 */
void script_validation();

/**
 * Returns true if the given script statement (body) is valid.
 */
bool script_is_valid(const Stmt* s);

	}
