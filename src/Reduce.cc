// See the file "COPYING" in the main distribution directory for copyright.

#include "ID.h"
#include "Expr.h"
#include "Reduce.h"


IntrusivePtr<ID> ReductionContext::GenTemporary()
	{
	return nullptr;
	}

IntrusivePtr<Expr> ReductionContext::GenTemporaryExpr()
	{
	return {AdoptRef{}, new NameExpr(GenTemporary())};
	}
