// See the file "COPYING" in the main distribution directory for copyright.

#include "ID.h"
#include "Var.h"
#include "Scope.h"
#include "Expr.h"
#include "Stmt.h"
#include "Reporter.h"
#include "Reduce.h"


class TempVar {
public:
	TempVar(int num, const IntrusivePtr<BroType>& t, IntrusivePtr<Expr> rhs);
	~TempVar()	{ delete name; }

	const char* Name() const	{ return name; }
	const BroType* Type() const	{ return type.get(); }
	const Expr* RHS() const		{ return rhs.get(); }

	IntrusivePtr<ID> Alias() const		{ return alias; }
	void SetAlias(IntrusivePtr<ID> id, const DefinitionItem* di,
			const RD_ptr& rds);

protected:
	char* name;
	const IntrusivePtr<BroType>& type;
	IntrusivePtr<Expr> rhs;
	IntrusivePtr<ID> alias;
	DefPoints dps;
};

TempVar::TempVar(int num, const IntrusivePtr<BroType>& t,
			IntrusivePtr<Expr> _rhs) : type(t)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = copy_string(buf);
	rhs = _rhs;
	alias = nullptr;
	dps = nullptr;
	}

void TempVar::SetAlias(IntrusivePtr<ID> _alias, const DefinitionItem* di,
			const RD_ptr& rds)
	{
	if ( alias )
		reporter->InternalError("Re-aliasing a temporary\n");

	alias = _alias;
	dps = rds->GetDefPoints(di);
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

IntrusivePtr<Expr> ReductionContext::GenTemporaryExpr(const IntrusivePtr<BroType>& t,
						IntrusivePtr<Expr> rhs)
	{
	return {AdoptRef{}, new NameExpr(GenTemporary(t, rhs))};
	}

bool ReductionContext::IsCSE(const NameExpr* lhs, const Expr* rhs)
	{
	auto lhs_id = lhs->Id();
	auto lhs_tmp = FindTemporary(lhs_id);

	if ( lhs_tmp && rhs->Tag() == EXPR_NAME )
		{
		auto rhs_id = rhs->AsNameExpr()->Id();
		IntrusivePtr<ID> rhs_id_ptr = {AdoptRef{}, rhs_id};
		auto rhs_rds = mgr->GetPreMaxRDs(rhs);
		auto rhs_di = mgr->GetConstIDReachingDef(rhs_id);
		lhs_tmp->SetAlias(rhs_id_ptr, rhs_di, rhs_rds);
		return true;
		}

	return false;
	}

Expr* ReductionContext::OptExpr(Expr* e)
	{
	IntrusivePtr<Stmt> opt_stmts;
	auto opt_e = e->Reduce(this, opt_stmts);

	if ( opt_stmts )
		reporter->InternalError("Generating new statements while optimizing\n");

	return opt_e;
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

IntrusivePtr<Expr> ReductionContext::UpdateExpr(IntrusivePtr<Expr> e)
	{
	if ( e->Tag() != EXPR_NAME )
		return e;

	auto n = e->AsNameExpr();
	auto id = n->Id();

	auto tmp_var = FindTemporary(id);
	if ( ! tmp_var )
		return e;

	if ( tmp_var->Alias() )
		return make_intrusive<NameExpr>(tmp_var->Alias());

	auto rhs = tmp_var->RHS();
	if ( rhs->Tag() != EXPR_CONST )
		return e;

	auto c = rhs->AsConstExpr();
	return make_intrusive<ConstExpr>(c->ValuePtr());
	}

IntrusivePtr<ID> ReductionContext::GenTemporary(const IntrusivePtr<BroType>& t,
						IntrusivePtr<Expr> rhs)
	{
	if ( Optimizing() )
		reporter->InternalError("Generating a new temporary while optimizing\n");

	auto temp = new TempVar(temps.length(), t, rhs);
	IntrusivePtr<ID> temp_id =
		install_ID(temp->Name(), nullptr, false, false);

	temp_id->SetType(t);

	temps.append(temp);
	ids_to_temps.insert(std::pair<const ID*, TempVar*>(temp_id.get(), temp));

	return temp_id;
	}

TempVar* ReductionContext::FindTemporary(const ID* id)
	{
	auto tmp = ids_to_temps.find(id);
	if ( tmp == ids_to_temps.end() )
		return nullptr;
	else
		return tmp->second;
	}
