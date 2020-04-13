// See the file "COPYING" in the main distribution directory for copyright.

#include "ID.h"
#include "Var.h"
#include "Scope.h"
#include "Expr.h"
#include "Stmt.h"
#include "Desc.h"
#include "Reporter.h"
#include "Reduce.h"


static char obj_desc_storage[8192];

static const char* obj_desc(const BroObj* o)
	{
	ODesc d;
	d.SetDoOrig(false);
	o->Describe(&d);
	d.SP();
	o->GetLocationInfo()->Describe(&d);

	strcpy(obj_desc_storage, d.Description());

	return obj_desc_storage;
	}

class TempVar {
public:
	TempVar(int num, const IntrusivePtr<BroType>& t, IntrusivePtr<Expr> rhs);
	~TempVar()	{ delete name; }

	const char* Name() const	{ return name; }
	const BroType* Type() const	{ return type.get(); }
	const Expr* RHS() const		{ return rhs.get(); }

	IntrusivePtr<ID> Id() const		{ return id; }
	void SetID(IntrusivePtr<ID> _id)	{ id = _id; }

	IntrusivePtr<ID> Alias() const		{ return alias; }
	const DefPoints* DPs() const		{ return dps; }
	void SetAlias(IntrusivePtr<ID> id, const DefPoints* dps);

	const RD_ptr& MaxRDs() const	{ return max_rds; }
	void SetMaxRDs(RD_ptr rds)	{ max_rds = rds; }

protected:
	char* name;
	IntrusivePtr<ID> id;
	const IntrusivePtr<BroType>& type;
	IntrusivePtr<Expr> rhs;
	IntrusivePtr<ID> alias;
	const DefPoints* dps;
	RD_ptr max_rds;
};

TempVar::TempVar(int num, const IntrusivePtr<BroType>& t,
			IntrusivePtr<Expr> _rhs) : type(t), dps(nullptr)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#%d", num);
	name = copy_string(buf);
	id = nullptr;
	rhs = _rhs;
	alias = nullptr;
	max_rds = nullptr;
	}

void TempVar::SetAlias(IntrusivePtr<ID> _alias, const DefPoints* _dps)
	{
	if ( alias )
		reporter->InternalError("Re-aliasing a temporary");

	alias = _alias;
	dps = _dps;
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

bool ReductionContext::SameDPs(const DefPoints* dp1, const DefPoints* dp2) const
	{
	if ( dp1 == dp2 )
		return true;

	// Given how we construct DPs, they should be element-by-element
	// equivalent; we don't have to worry about reordering.
	if ( dp1->length() != dp2->length() )
		return false;

	for ( auto i = 0; i < dp1->length(); ++i )
		if ( ! (*dp1)[i].SameAs((*dp2)[i]) )
			return false;

	return true;
	}

bool ReductionContext::SameVal(const Val* v1, const Val* v2) const
	{
	if ( is_atomic_val(v1) )
		return same_atomic_val(v1, v2);
	else
		return v1 == v2;
	}

bool ReductionContext::SameOp(const Expr* op1, const Expr* op2) const
	{
	if ( op1->Tag() != op2->Tag() )
		return false;

	if ( op1->Tag() == EXPR_NAME )
		{
		auto op1_n = op1->AsNameExpr();
		auto op2_n = op2->AsNameExpr();

		auto op1_id = op1_n->Id();
		auto op2_id = op2_n->Id();

		if ( op1_id != op2_id )
			return false;

		auto di = mgr->GetConstIDReachingDef(op1_id);

		auto op1_rds = mgr->GetPreMaxRDs(op1);
		auto op2_rds = mgr->GetPreMaxRDs(op2);

		if ( op1_rds == op2_rds )
			return true;

		auto op1_dps = op1_rds->GetDefPoints(di);
		auto op2_dps = op2_rds->GetDefPoints(di);

		return SameDPs(op1_dps, op2_dps);
		}

	else if ( op1->Tag() == EXPR_CONST )
		{
		auto op1_c = op1->AsConstExpr();
		auto op2_c = op2->AsConstExpr();

		auto op1_v = op1_c->Value();
		auto op2_v = op2_c->Value();

		return SameVal(op1_v, op2_v);
		}

	else
		reporter->InternalError("bad singleton tag");
	}

// Returns true if the RHS associated with the expression "tmp" is
// equivalent to orig_rhs, given the reaching definitions associated
// with lhs.
bool ReductionContext::SameExpr(const Expr* orig_rhs, const TempVar* tmp) const
	{
	auto e = tmp->RHS();

	if ( e == orig_rhs )
		return true;

	if ( e->Tag() != orig_rhs->Tag() )
		return false;

	switch ( e->Tag() ) {
	case EXPR_NAME:
	case EXPR_CONST:
		return SameOp(e, orig_rhs);

	case EXPR_CLONE:
	case EXPR_RECORD_CONSTRUCTOR:
	case EXPR_TABLE_CONSTRUCTOR:
	case EXPR_SET_CONSTRUCTOR:
	case EXPR_VECTOR_CONSTRUCTOR:
		// These always generate a new value.
		return false;

	case EXPR_INCR:
	case EXPR_DECR:
	case EXPR_AND_AND:
	case EXPR_OR_OR:
	case EXPR_ASSIGN:
	case EXPR_FIELD_ASSIGN:
	case EXPR_INDEX_SLICE_ASSIGN:
	case EXPR_COND:
		// All of these should have been translated into something
		// else.
		reporter->InternalError("Unexpected tag in ReductionContext::SameExpr");

	case EXPR_LIST:

	case EXPR_CALL:

	case EXPR_LAMBDA:
		return false;

	case EXPR_EVENT:
	case EXPR_SCHEDULE:

	default:
		if ( e->HaveGetOp() )
			return SameOp(e->GetOp(), orig_rhs->GetOp());

		else if ( e->HaveGetOps() )
			return SameOp(e->GetOp1(), orig_rhs->GetOp1()) &&
				SameOp(e->GetOp2(), orig_rhs->GetOp2());

		else
			reporter->InternalError("Bad default in ReductionContext::SameExpr");
	}
	}

// Find a temporary, if any, whose RHS matches the given "rhs", using
// the reaching defs associated with "lhs".
IntrusivePtr<ID> ReductionContext::FindExprTmp(const Expr* rhs,
						const Expr* lhs) const
	{
	for ( int i = 0; i < expr_temps.length(); ++i )
		{
		auto et_i = expr_temps[i];
		if ( et_i->Alias() )
			reporter->InternalError("Encountered ExprTmp with an alias");

		if ( SameExpr(rhs, et_i) )
			{
			// Make sure its value always makes it here.
			auto id = et_i->Id();

			// We use lhs in the following rather than rhs
			// because the RHS can get rewritten (for example,
			// due to folding) after we generate RDs, and
			// thus might not have any.
			if ( ! mgr->HasPreMinRD(lhs, id.get()) )
				// Value isn't guaranteed to make it here.
				continue;

			return et_i->Id();
			}
		}

	return nullptr;
	}

bool ReductionContext::IsCSE(const NameExpr* lhs, const Expr* rhs)
	{
	bool did_reduction = false;

	auto lhs_id = lhs->Id();
	auto lhs_tmp = FindTemporary(lhs_id);
	if ( ! mgr->HasPreMaxRDs(lhs) )
		reporter->InternalError("RD confusion in ReductionContext::IsCSE");
	auto lhs_max_rds = mgr->GetPreMaxRDs(lhs);

	auto rhs_tmp = FindExprTmp(rhs, lhs);

	IntrusivePtr<Expr> new_rhs;
	if ( rhs_tmp )
		{
		new_rhs = make_intrusive<NameExpr>(rhs_tmp);
		rhs = new_rhs.get();
		did_reduction = true;
		}

	if ( lhs_tmp )
		{
		if ( rhs->Tag() == EXPR_NAME )
			{ // create alias
			auto rhs_id = rhs->AsNameExpr()->Id();
			IntrusivePtr<ID> rhs_id_ptr = {AdoptRef{}, rhs_id};
			auto rhs_di = mgr->GetConstIDReachingDef(rhs_id);
			auto dps = lhs_max_rds->GetDefPoints(rhs_di);
			lhs_tmp->SetAlias(rhs_id_ptr, dps);
			return true;
			}

		expr_temps.append(lhs_tmp);
		}

	return did_reduction;
	}

Expr* ReductionContext::OptExpr(Expr* e)
	{
	IntrusivePtr<Stmt> opt_stmts;
	auto opt_e = e->Reduce(this, opt_stmts);

	if ( opt_stmts )
		reporter->InternalError("Generating new statements while optimizing");

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

	auto alias = tmp_var->Alias();
	if ( alias )
		{
		// Make sure that the definition points for the
		// alias here are the same as when the alias
		// was created.
		auto alias_tmp = FindTemporary(alias.get());

		if ( alias_tmp )
			{
			if ( alias_tmp->Alias() )
				reporter->InternalError("double alias");

			// Temporaries always have only one definition point,
			return make_intrusive<NameExpr>(alias);
			}

		auto e_max_rds = mgr->GetPreMaxRDs(e.get());
		auto alias_di = mgr->GetConstIDReachingDef(alias.get());
		auto alias_dps = e_max_rds->GetDefPoints(alias_di);

		if ( SameDPs(alias_dps, tmp_var->DPs()) )
			// ### may need to attach RDs here for
			// future comparisons
			return make_intrusive<NameExpr>(alias);
		else
			{
			printf("DPs differ: %s\n", obj_desc(e.get()));
			return e;
			}
		}

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
		reporter->InternalError("Generating a new temporary while optimizing");

	auto temp = new TempVar(temps.length(), t, rhs);
	IntrusivePtr<ID> temp_id =
		install_ID(temp->Name(), nullptr, false, false);

	temp->SetID(temp_id);
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
