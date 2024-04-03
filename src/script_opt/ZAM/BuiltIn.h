// See the file "COPYING" in the main distribution directory for copyright.

// ZAM classes for built-in functions.

#pragma once

#include "zeek/Expr.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

// If the given expression corresponds to a call to a ZAM built-in,
// then compiles the call and returns true.  Otherwise, returns false.
extern bool IsZAM_BuiltIn(ZAMCompiler* zam, const Expr* e);

} // namespace zeek::detail
