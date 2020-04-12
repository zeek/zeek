// See the file "COPYING" in the main distribution directory for copyright.

#include "ID.h"
#include "Var.h"
#include "Scope.h"
#include "Expr.h"
#include "Stmt.h"
#include "Reporter.h"
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
	mgr = nullptr;
	}

ReductionContext::~ReductionContext()
	{
	for ( int i = 0; i < temps.length(); ++i )
		delete temps[i];
	}

IntrusivePtr<ID> ReductionContext::GenTemporary(const IntrusivePtr<BroType>& t)
	{
	if ( mgr )
		reporter->InternalError("Generating a new temporary while optimizing\n");

	auto temp = new TempVar(temps.length(), t);
	IntrusivePtr<ID> temp_id =
		install_ID(temp->Name(), nullptr, false, false);

	temp_id->SetType(t);

	temps.append(temp);

	return temp_id;
	}

IntrusivePtr<Expr> ReductionContext::GenTemporaryExpr(const IntrusivePtr<BroType>& t)
	{
	return {AdoptRef{}, new NameExpr(GenTemporary(t))};
	}

bool ReductionContext::IsCSE(const NameExpr* lhs, const Expr* rhs)
	{
	return false;
	}

Expr* ReductionContext::OptExpr(Expr* e)
	{
	return e->Ref();
	}

IntrusivePtr<Expr> ReductionContext::OptExpr(IntrusivePtr<Expr> e_ptr)
	{
	auto e = e_ptr.get();
	auto new_e = OptExpr(e);
	if ( new_e == e )
		{
		// Undo the Ref() that occurred.
		Unref(e);
		return e_ptr;
		}

	return {AdoptRef{}, new_e};
	}
