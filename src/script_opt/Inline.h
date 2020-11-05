// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Expr.h"
#include "Func.h"
#include "Scope.h"

#include <unordered_set>


namespace zeek::detail {

class FuncInfo;

class Inliner {
public:
	Inliner(std::vector<FuncInfo*>& _funcs, bool _report_recursive)
	: funcs(_funcs), report_recursive(_report_recursive)
		{ Analyze(); }

	// Either returns the original CallExpr if it's not inline-able,
	// or an InlineExpr if it is.
	ExprPtr CheckForInlining(CallExprPtr c);

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

	// Whether to generate a report about functions both directly and
	// indirectly recursive.
	bool report_recursive;
};


} // namespace zeek::detail
