// See the file "COPYING" in the main distribution directory for copyright.

#include "ID.h"
#include "Var.h"
#include "Scope.h"
#include "Expr.h"
#include "Stmt.h"
#include "Reduce.h"


TempVar::TempVar(int num, const IntrusivePtr<BroType>& t) : type(t)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = copy_string(buf);
	}

ReductionContext::ReductionContext(Scope* s)
	{
	scope = s;
	}

ReductionContext::~ReductionContext()
	{
	for ( int i = 0; i < temps.length(); ++i )
		delete temps[i];
	}

IntrusivePtr<ID> ReductionContext::GenTemporary(const IntrusivePtr<BroType>& t)
	{
	auto temp = new TempVar(temps.length(), t);
	IntrusivePtr<ID> temp_id =
		{AdoptRef{}, new ID(temp->Name(), SCOPE_FUNCTION, false)};

	add_local(temp_id, t, INIT_NONE, nullptr, nullptr, VAR_REGULAR);

	temps.append(temp);

	return temp_id;
	}

IntrusivePtr<Expr> ReductionContext::GenTemporaryExpr(const IntrusivePtr<BroType>& t)
	{
	return {AdoptRef{}, new NameExpr(GenTemporary(t))};
	}
