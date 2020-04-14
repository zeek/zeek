// See the file "COPYING" in the main distribution directory for copyright.

#include "IntrusivePtr.h"
#include "DefSetsMgr.h"

class ID;
class Expr;
class TempVar;

class ReductionContext {
public:
	ReductionContext(Scope* s);
	~ReductionContext();

	void SetDefSetsMgr(const DefSetsMgr* _mgr)	{ mgr = _mgr; }

	IntrusivePtr<Expr> GenTemporaryExpr(const IntrusivePtr<BroType>& t,
						IntrusivePtr<Expr> rhs);

	int NumTemps() const		{ return temps.length(); }

	bool Optimizing() const		{ return mgr != nullptr; }

	// Given the LHS and RHS of an assignment, returns true
	// if the RHS is a common subexpression (meaning that the
	// current assignment statement should be deleted).  In
	// that case, has the side effect of associating an alias
	// for the LHS with the temporary holding the equivalent RHS.
	//
	// Assumes reduction (including alias propagation) has
	// already been applied.
	bool IsCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs);

	Expr* OptExpr(Expr* e);
	IntrusivePtr<Expr> OptExpr(IntrusivePtr<Expr> e);

	IntrusivePtr<Expr> UpdateExpr(IntrusivePtr<Expr> e);

protected:
	bool SameDPs(const DefPoints* dp1, const DefPoints* dp2) const;
	bool SameVal(const Val* v1, const Val* v2) const;
	IntrusivePtr<Expr> NewVarUsage(IntrusivePtr<ID> var,
					const DefPoints* dps);
	const DefPoints* GetDefPoints(const NameExpr* var);
	const DefPoints* FindDefPoints(const NameExpr* var) const;
	void AddDefPoints(const NameExpr* var, const DefPoints* dps);
	bool SameOp(const Expr* op1, const Expr* op2);
	bool SameOp(const IntrusivePtr<Expr>& op1,
			const IntrusivePtr<Expr>& op2)
		{ return SameOp(op1.get(), op2.get()); }
	bool SameExpr(const Expr* e1, const Expr* e2);

	IntrusivePtr<ID> FindExprTmp(const Expr* rhs, const Expr* lhs);
	IntrusivePtr<ID> GenTemporary(const IntrusivePtr<BroType>& t,
					IntrusivePtr<Expr> rhs);
	TempVar* FindTemporary(const ID* id) const;

	Scope* scope;
	PList<TempVar> temps;

	// Temps for which we've processed their associated expression
	// (and they didn't wind up being aliases).
	PList<TempVar> expr_temps;

	// Let's us go from an identifier to an associated temporary
	// variable, if it corresponds to one.
	std::map<const ID*, TempVar*> ids_to_temps;

	// For a given usage of a variable's value, return the definition
	// points associated with its use at that point.  We use this
	// both as a cache (populating it every time we do a more
	// laborious lookup), and proactively when creating new
	// references to variables.
	std::map<const NameExpr*, const DefPoints*> var_usage_to_DPs;

	const DefSetsMgr* mgr;
};
