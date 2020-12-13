// See the file "COPYING" in the main distribution directory for copyright.

// Classes for controlling/orchestrating script optimization & compilation.

#pragma once

#include "zeek/Func.h"
#include "zeek/Expr.h"
#include "zeek/Scope.h"

namespace zeek { struct Options; }

namespace zeek::detail {


// Flags controlling what sorts of analysis to do.

struct AnalyOpt {
	// If true, do global inlining.
	bool inliner = false;

	// If true, report which functions are directly and indirectly
	// recursive, and exit.  Only germane if running the inliner.
	bool report_recursive = false;
};


class ProfileFunc;

using ScriptFuncPtr = IntrusivePtr<ScriptFunc>;

// Info we need for tracking an instance of a function.
class FuncInfo {
public:
	FuncInfo(ScriptFuncPtr _func, ScopePtr _scope, StmtPtr _body)
		{
		func = std::move(_func);
		scope = std::move(_scope);
		body = std::move(_body);
		}

	~FuncInfo();

	ScriptFunc* Func()	{ return func.get(); }
	ScriptFuncPtr FuncPtr()	{ return func; }
	ScopePtr Scope()	{ return scope; }
	StmtPtr Body()		{ return body; }
	ProfileFunc* Profile()	{ return pf; }
	const char* SaveFile()	{ return save_file; }

	void SetProfile(ProfileFunc* _pf)	{ pf = _pf; }
	void SetSaveFile(const char* _sf);

protected:
	ScriptFuncPtr func;
	ScopePtr scope;
	StmtPtr body;
	ProfileFunc* pf = nullptr;

	// If we're saving this function in a file, this is the name
	// of the file to use.
	char* save_file = nullptr;
};


// We track which functions are definitely not recursive.  We do this
// as the negative, rather than tracking functions known to be recursive,
// so that if we don't do the analysis at all (it's driven by inlining),
// we err on the conservative side and assume every function is recursive.
extern std::unordered_set<const Func*> non_recursive_funcs;

// Analyze a given function for optimization.
extern void analyze_func(ScriptFuncPtr f);

// Analyze all of the parsed scripts collectively for optimization.
extern void analyze_scripts(Options& opts);


} // namespace zeek::detail
