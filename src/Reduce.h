// See the file "COPYING" in the main distribution directory for copyright.

#include "IntrusivePtr.h"
#include "DefSetsMgr.h"

class ID;
class Expr;

class TempVar {
public:
	TempVar(int num, const IntrusivePtr<BroType>& t);
	~TempVar()	{ delete name; }

	const char* Name() const	{ return name; }
	const BroType* Type() const	{ return type.get(); }

protected:
	char* name;
	const IntrusivePtr<BroType>& type;
};

class ReductionContext {
public:
	ReductionContext(Scope* s);
	~ReductionContext();

	void SetDefSetsMgr(const DefSetsMgr* _mgr)	{ mgr = _mgr; }

	IntrusivePtr<ID> GenTemporary(const IntrusivePtr<BroType>& t);
	IntrusivePtr<Expr> GenTemporaryExpr(const IntrusivePtr<BroType>& t);

	int NumTemps() const		{ return temps.length(); }

protected:
	Scope* scope;
	PList<TempVar> temps;

	const DefSetsMgr* mgr;
};
