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

	bool IsCSE(const NameExpr* lhs, const Expr* rhs);

	Expr* OptExpr(Expr* e);
	IntrusivePtr<Expr> OptExpr(IntrusivePtr<Expr> e);

	IntrusivePtr<Expr> UpdateExpr(IntrusivePtr<Expr> e);

protected:
	IntrusivePtr<ID> GenTemporary(const IntrusivePtr<BroType>& t,
					IntrusivePtr<Expr> rhs);

	Scope* scope;
	PList<TempVar> temps;
	std::map<ID*, TempVar*> ids_to_temps;

	const DefSetsMgr* mgr;
};
