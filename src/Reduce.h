// See the file "COPYING" in the main distribution directory for copyright.

#include "IntrusivePtr.h"
#include "DefSetsMgr.h"

class ID;
class Expr;
class TempVar;

class Reducer {
public:
	Reducer(Scope* s);
	~Reducer();

	void SetDefSetsMgr(const DefSetsMgr* _mgr)	{ mgr = _mgr; }

	IntrusivePtr<Expr> GenTemporaryExpr(const IntrusivePtr<BroType>& t,
						IntrusivePtr<Expr> rhs);

	int NumTemps() const		{ return temps.length(); }
	bool IsTemporary(const ID* id) const
		{ return FindTemporary(id) != nullptr; }
	bool IsConstantVar(const ID* id) const
		{ return constant_vars.find(id) != constant_vars.end(); }

	bool Optimizing() const	
		{ return ! IsPruning() && mgr != nullptr; }

	bool IsPruning() const		{ return omitted_stmts.size() > 0; }
	bool ShouldOmitStmt(const Stmt* s) const
		{ return omitted_stmts.find(s) != omitted_stmts.end(); }

	// Tells the reducer to prune the given statement during the
	// next reduction pass.
	void AddStmtToOmit(const Stmt* s)	{ omitted_stmts.insert(s); }

	// Tells the reducer that it can reclaim the storage associated
	// with the omitted statements.
	void ResetOmittedStmts()		{ omitted_stmts.clear(); }

	// Given the LHS and RHS of an assignment, returns true
	// if the RHS is a common subexpression (meaning that the
	// current assignment statement should be deleted).  In
	// that case, has the side effect of associating an alias
	// for the LHS with the temporary holding the equivalent RHS.
	//
	// Assumes reduction (including alias propagation) has
	// already been applied.
	bool IsCSE(const AssignExpr* a, const NameExpr* lhs, const Expr* rhs);

	// Given an lhs=rhs statement followed by succ_stmt, returns
	// a (new) merge of the two if they're of the form tmp=rhs, var=tmp;
	// otherwise, nil.
	Stmt* MergeStmts(const NameExpr* lhs, IntrusivePtr<Expr> rhs,
						Stmt* succ_stmt);

	Expr* OptExpr(Expr* e);
	IntrusivePtr<Expr> OptExpr(IntrusivePtr<Expr> e);

	IntrusivePtr<Expr> UpdateExpr(IntrusivePtr<Expr> e);

protected:
	bool SameDPs(const DefPoints* dp1, const DefPoints* dp2) const;
	bool SameVal(const Val* v1, const Val* v2) const;

	IntrusivePtr<Expr> NewVarUsage(IntrusivePtr<ID> var,
					const DefPoints* dps, const Expr* orig);

	const DefPoints* GetDefPoints(const NameExpr* var);
	const DefPoints* FindDefPoints(const NameExpr* var) const;
	void SetDefPoints(const NameExpr* var, const DefPoints* dps);

	// Returns true if op1 and op2 represent the same operand, given
	// the reaching definitions available at their usages (e1 and e2).
	bool SameOp(const Expr* op1, const Expr* op2);
	bool SameOp(const IntrusivePtr<Expr>& op1,
			const IntrusivePtr<Expr>& op2)
		{ return SameOp(op1.get(), op2.get()); }

	bool SameExpr(const Expr* e1, const Expr* e2);

	IntrusivePtr<ID> FindExprTmp(const Expr* rhs, const Expr* lhs,
					const TempVar* lhs_tmp);
	IntrusivePtr<ID> GenTemporary(const IntrusivePtr<BroType>& t,
					IntrusivePtr<Expr> rhs);
	TempVar* FindTemporary(const ID* id) const;

	// This is the heart of constant propagation.  Given an identifier
	// and a set of definition points for it, if its value is constant
	// then returns the corresponding ConstExpr with the value.
	const ConstExpr* CheckForConst(const IntrusivePtr<ID>& id,
					const DefPoints* dps) const;

	void TrackExprReplacement(const Expr* orig, const Expr* e);
	const BroObj* GetRDLookupObj(const Expr* e) const;

	Scope* scope;
	PList<TempVar> temps;

	// Temps for which we've processed their associated expression
	// (and they didn't wind up being aliases).
	PList<TempVar> expr_temps;

	// Let's us go from an identifier to an associated temporary
	// variable, if it corresponds to one.
	std::unordered_map<const ID*, TempVar*> ids_to_temps;

	// For a given usage of a variable's value, return the definition
	// points associated with its use at that point.  We use this
	// both as a cache (populating it every time we do a more
	// laborious lookup), and proactively when creating new
	// references to variables.
	std::unordered_map<const NameExpr*, const DefPoints*> var_usage_to_DPs;

	// Tracks which (non-temporary) variables had constant
	// values used for constant propagation.
	std::unordered_set<const ID*> constant_vars;

	// For a new expression we've created, map it to the expression
	// it's replacing.  This allows us to locate the RDs associated
	// with the usage.
	std::unordered_map<const Expr*, const Expr*> new_expr_to_orig;

	std::unordered_set<const Stmt*> omitted_stmts;

	const DefSetsMgr* mgr;
};

// Used for debugging, to communicate which expression wasn't
// reduced when we expected them all to be.
extern const Expr* non_reduced_perp;
extern bool checking_reduction;

// Used to report a non-reduced expression.
extern bool NonReduced(const Expr* perp);
