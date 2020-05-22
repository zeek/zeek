// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Func.h"
#include "Expr.h"
#include "Scope.h"

class ProfileFunc;

// Info we need for tracking an instance of a function.
class FuncInfo {
public:
	FuncInfo(BroFunc* _func, IntrusivePtr<Scope> _scope,
			IntrusivePtr<Stmt> _body)
		{
		func = _func;
		scope = _scope;
		body = _body;
		pf = nullptr;
		}

	~FuncInfo();

	BroFunc* func;
	IntrusivePtr<Scope> scope;
	IntrusivePtr<Stmt> body;
	ProfileFunc* pf;
};


extern void analyze_func(BroFunc* f);
extern void analyze_scripts();
