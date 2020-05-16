// See the file "COPYING" in the main distribution directory for copyright.

#include "Compile.h"
#include "Traverse.h"


const Stmt* curr_stmt;


TraversalCode Compiler::Traverse(TraversalCallback* cb) const
	{
	TraversalCode tc = cb->PreStmt(this);
	HANDLE_TC_STMT_PRE(tc);

	tc = cb->PostStmt(this);
	HANDLE_TC_STMT_POST(tc);
	}
