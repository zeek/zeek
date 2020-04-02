// See the file "COPYING" in the main distribution directory for copyright.

#include "IntrusivePtr.h"

class ID;
class Expr;

class ReductionContext {
public:
	IntrusivePtr<ID> GenTemporary();
	IntrusivePtr<Expr> GenTemporaryExpr();
};
