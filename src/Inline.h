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

	bool WasInlined(Func* f)	{ return inline_ables.count(f) > 0; }

protected:
	void Analyze();

	void InlineFunction(FuncInfo* f);

	// Information about all of the functions (and events/hooks) in
	// the full set of scripts.
	std::vector<FuncInfo*>& funcs;

	// Functions we've determined to be (or turned into) leaves,
	// so suitable for inlining.
	std::unordered_set<Func*> inline_ables;

	// As we do inlining for a given function, this tracks the
	// largest frame size of any inlined function.
	int max_inlined_frame_size;

	// The size of the frame of the currently-being-inlined function,
	// prior to increasing it to accommodate inlining.
	int curr_frame_size;
};
