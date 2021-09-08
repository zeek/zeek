// See the file "COPYING" in the main distribution directory for copyright.

// Auxiliary information associated with expressions to aid script
// optimization.

#pragma once

namespace zeek::detail {

class ExprOptInfo {
public:
	// The AST number of the statement in which this expression
	// appears.
	int stmt_num = -1;	// -1 = not assigned yet
};

} // namespace zeek::detail
