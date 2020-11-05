// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Class for managing temporary variables created during statement reduction
// for compilation.

#include "ID.h"
#include "Expr.h"

#ifdef NOT_YET
#include "ReachingDefs.h"
#endif


namespace zeek::detail {

class TempVar {
public:
	TempVar(int num, const TypePtr& t, ExprPtr rhs);
	~TempVar()	{ delete name; }

	const char* Name() const	{ return name; }
	const zeek::Type* Type() const	{ return type.get(); }

	IDPtr Id() const		{ return id; }
	void SetID(IDPtr _id)	{ id = _id; }

#ifdef NOT_YET
	const Expr* RHS() const		{ return rhs.get(); }
	void Deactivate()	{ active = false; }
	bool IsActive() const	{ return active; }

	const ConstExpr* Const() const	{ return const_expr; }
	// The most use of "const" in any single line in the Zeek
	// codebase :-P ... though only by one!
	void SetConst(const ConstExpr* _const) { const_expr = _const; }

	IDPtr Alias() const		{ return alias; }
	const DefPoints* DPs() const		{ return dps; }
	void SetAlias(IDPtr id, const DefPoints* dps);
	void SetDPs(const DefPoints* _dps);

	const RD_ptr& MaxRDs() const	{ return max_rds; }
	void SetMaxRDs(RD_ptr rds)	{ max_rds = rds; }
#endif

protected:
	char* name;
	IDPtr id;
	const TypePtr& type;
	ExprPtr rhs;
#ifdef NOT_YET
	bool active = true;
	const ConstExpr* const_expr;
	IDPtr alias;
	const DefPoints* dps;
	RD_ptr max_rds;
#endif
};

} // zeek::detail
