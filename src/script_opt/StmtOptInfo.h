// See the file "COPYING" in the main distribution directory for copyright.

// Auxiliary information associated with statements to aid script
// optimization.

#pragma once

namespace zeek::detail {

class StmtOptInfo {
public:
	// We number statements by their traversal order in the AST.
	int stmt_num = -1;	// -1 = not assigned yet

	// The confluence block nesting associated with the statement.
	// We number these using 0 for the outermost block of a function
	// (which, strictly speaking, isn't a confluence block).
	int block_level = -1;

	// True if we observe that there is a branch out of the statement
	// to just beyond its extent, such as due to a "break".
	bool contains_branch_beyond = false;
};

} // namespace zeek::detail
