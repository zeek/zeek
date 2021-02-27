// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Class for managing temporary variables created during statement reduction
// for compilation.

#include <string>

#include "zeek/ID.h"
#include "zeek/Expr.h"
#include "zeek/script_opt/ReachingDefs.h"

namespace zeek::detail {

class TempVar {
public:
	TempVar(int num, const TypePtr& t, ExprPtr rhs);

	const char* Name() const	{ return name.data(); }
	const zeek::Type* Type() const	{ return type.get(); }
	const Expr* RHS() const		{ return rhs.get(); }

	IDPtr Id() const	{ return id; }
	void SetID(IDPtr _id)	{ id = std::move(_id); }
	void Deactivate()	{ active = false; }
	bool IsActive() const	{ return active; }

	// Associated constant expression, if any.
	const ConstExpr* Const() const	{ return const_expr; }

	// The most use of "const" in any single line in the Zeek
	// codebase :-P ... though only by one!
	void SetConst(const ConstExpr* _const) { const_expr = _const; }

	IDPtr Alias() const			{ return alias; }
	const DefPoints* DPs() const		{ return dps; }
	void SetAlias(IDPtr id, const DefPoints* dps);
	void SetDPs(const DefPoints* _dps);

	const RDPtr& MaxRDs() const	{ return max_rds; }
	void SetMaxRDs(RDPtr rds)	{ max_rds = rds; }

protected:
	std::string name;
	IDPtr id;
	const TypePtr& type;
	ExprPtr rhs;
	bool active = true;
	const ConstExpr* const_expr = nullptr;
	IDPtr alias;
	const DefPoints* dps = nullptr;
	RDPtr max_rds;
};

} // zeek::detail
