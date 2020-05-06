// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Class for managing temporary variables created during statement reduction
// for compilation.

#include "ID.h"
#include "Expr.h"
#include "ReachingDefs.h"


class TempVar {
public:
	TempVar(int num, const IntrusivePtr<BroType>& t, IntrusivePtr<Expr> rhs);
	~TempVar()	{ delete name; }

	const char* Name() const	{ return name; }
	const BroType* Type() const	{ return type.get(); }
	const Expr* RHS() const		{ return rhs.get(); }

	IntrusivePtr<ID> Id() const		{ return id; }
	void SetID(IntrusivePtr<ID> _id)	{ id = _id; }

	void Deactivate()	{ active = false; }
	bool IsActive() const	{ return active; }

	const ConstExpr* Const() const	{ return const_expr; }
	// Surely the most use of "const" in any single line in
	// the Zeek codebase :-P.
	void SetConst(const ConstExpr* _const) { const_expr = _const; }

	IntrusivePtr<ID> Alias() const		{ return alias; }
	const DefPoints* DPs() const		{ return dps; }
	void SetAlias(IntrusivePtr<ID> id, const DefPoints* dps);
	void SetDPs(const DefPoints* _dps);

	const RD_ptr& MaxRDs() const	{ return max_rds; }
	void SetMaxRDs(RD_ptr rds)	{ max_rds = rds; }

protected:
	char* name;
	IntrusivePtr<ID> id;
	const IntrusivePtr<BroType>& type;
	IntrusivePtr<Expr> rhs;
	bool active = true;
	const ConstExpr* const_expr;
	IntrusivePtr<ID> alias;
	const DefPoints* dps;
	RD_ptr max_rds;
};
