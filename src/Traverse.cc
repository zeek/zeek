// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Traverse.h"

#include "zeek/Scope.h"
#include "zeek/Stmt.h"
#include "zeek/input.h"

namespace zeek::detail
	{

TraversalCode traverse_all(TraversalCallback* cb)
	{
	if ( ! global_scope() )
		return TC_CONTINUE;

	if ( ! stmts )
		// May be null when parsing fails.
		return TC_CONTINUE;

	cb->current_scope = global_scope();

	TraversalCode tc = global_scope()->Traverse(cb);

	HANDLE_TC_STMT_PRE(tc);
	tc = stmts->Traverse(cb);
	HANDLE_TC_STMT_POST(tc);
	}

	} // namespace zeek::detail
