// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Func.h"
#include "Scope.h"

#include <unordered_set>

class FuncInfo;

class Inliner {
public:
	Inliner(std::vector<FuncInfo*>& _funcs) : funcs(_funcs)
		{ Analyze(); }

	// Either returns the original CallExpr if it's not inline-able,
	// or an InlineExpr if it is.  If the former, it has been Ref()'d,
	// so what's new is always something that the caller should take
	// possession of.
	Expr* CheckForInlining(CallExpr* c);

protected:
	void Analyze();

	bool IsInlineAble(FuncInfo* f, std::unordered_set<Func*>& inline_ables);

	std::vector<FuncInfo*>& funcs;
};
