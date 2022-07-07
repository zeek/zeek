// See the file "COPYING" in the main distribution directory for copyright.

// Class that manages the process of (recursively) inlining function bodies.

#pragma once

#include <unordered_set>

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"

namespace zeek::detail
	{

class FuncInfo;

class Inliner
	{
public:
	// First argument is a collection of information about *all* of
	// the script functions.  Second argument states whether to report
	// recursive functions (of interest as they're not in-lineable).
	Inliner(std::vector<FuncInfo>& _funcs, bool _report_recursive)
		: funcs(_funcs), report_recursive(_report_recursive)
		{
		Analyze();
		}

	// Either returns the original CallExpr if it's not inline-able;
	// or an InlineExpr if it is; or nil if further inlining should stop.
	ExprPtr CheckForInlining(CallExprPtr c);

	// True if the given function has been inlined.
	bool WasInlined(const Func* f) { return inline_ables.count(f) > 0; }

protected:
	// Driver routine that analyzes all of the script functions and
	// recursively inlines eligible ones.
	void Analyze();

	// Recursively inlines any calls associated with the given function.
	void InlineFunction(FuncInfo* f);

	// Information about all of the functions (and events/hooks) in
	// the full set of scripts.
	std::vector<FuncInfo>& funcs;

	// Functions that we've determined to be suitable for inlining.
	std::unordered_set<const Func*> inline_ables;

	// As we do inlining for a given function, this tracks the
	// largest frame size of any inlined function.
	int max_inlined_frame_size;

	// The size of the frame of the currently-being-inlined function,
	// prior to increasing it to accommodate inlining.
	int curr_frame_size;

	// The number of statements and expressions in the function being
	// inlined.  Dynamically updated as the inlining proceeds.  Used
	// to cap inlining complexity.
	int num_stmts;
	int num_exprs;

	// Whether to generate a report about functions either directly and
	// indirectly recursive.
	bool report_recursive;
	};

	} // namespace zeek::detail
