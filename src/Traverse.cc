// See the file "COPYING" in the main distribution directory for copyright.

#include "Scope.h"
#include "Traverse.h"
#include "input.h"

TraversalCode traverse_all(TraversalCallback* cb)
	{
	if ( ! global_scope() )
		return TC_CONTINUE;

	cb->current_scope = global_scope();

	TraversalCode tc = global_scope()->Traverse(cb);

	HANDLE_TC_STMT_PRE(tc);
	tc = stmts->Traverse(cb);
	HANDLE_TC_STMT_POST(tc);
	}
