// See the file "COPYING" in the main distribution directory for copyright.

// Definitions associated with type attributes.

#pragma once

namespace zeek::detail
	{

enum AttrExprType
	{
	AE_NONE, // attribute doesn't have an expression
	AE_CONST, // easy expression - a constant (ConstExpr)
	AE_NAME, // easy - a global (NameExpr)
	AE_RECORD, // an empty record cast to a given type
	AE_CALL, // everything else - requires a lambda, essentially
	};

	} // zeek::detail
