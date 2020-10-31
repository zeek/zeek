// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Func.h"
#include "Expr.h"
#include "Scope.h"

namespace zeek { struct Options; }

namespace zeek::detail {


// Flags controlling what sorts of analysis to do.

struct AnalyOpt {
#ifdef NOT_YET
	// Whether to analyze scripts.
	bool activate = false;

	// If non-nil, then only analyze the given function/event/hook.
	const char* only_func = nullptr;

	// If true, then generate a detailed dynamic execution profile
	// for generate code.  A huge volume of output and slows down
	// executation roughly 2x.
	bool report_profile = false;

	// If non-zero, looks for variables that are used-but-possibly-not-set,
	// or set-but-not-used.
	//
	// If > 1, also reports on uses of uninitialized record fields and
	// analyzes nested records in depth.  Warning: with the current
	// data structures this greatly increases analysis time.
	int usage_issues = 0;
	bool find_deep_uninits = false;

	// If true, activates tracing for the generation of minimum/maximum
	// reaching-defs.
	bool min_rd_trace = false;
	bool max_rd_trace = false;

	// If true, dump out the use-defs for each analyzed function.
	bool ud_dump = false;
#endif

	// If true, do global inlining.  Not affected by only_func.
	bool inliner = false;

	// If true, report which functions are directly and indirectly
	// recursive, and exit.  Only germane if running the inliner.
	bool report_recursive = false;

#ifdef NOT_YET
	// If true, report on which functions cannot be compiled, and exit.
	bool report_uncompilable = false;

	// If true, report on orphan functions and events.
	bool report_orphans = false;

	// If true, do optimization on reduced interpreted scripts.
	bool optimize = false;

	// If true, compile interpreted scripts to ZAM.
	bool compile = false;

	// If true, suppress low-level optimization on ZAM instructions.
	bool no_ZAM_opt = false;

	// If true, dump out the ZAM code.  This is always done if
	// only_func is set (and compile is set).
	bool dump_code = false;

	// If true, dump out transformed code: the results of reducing
	// interpreted scripts, and, if optimize is set, of then optimizing
	// them.  Always done if only_func is set.
	bool dump_xform = false;

	// If true, do not load saved ZAM code.
	bool no_load = false;

	// If true, do not save new ZAM code.
	bool no_save = false;

	// Delete (and do not replace) any matching ZAM save files.
	bool delete_save_files = false;

	// Overwrite any matching ZAM save files.
	bool overwrite_save_files = false;
#endif

};


class ProfileFunc;

// Info we need for tracking an instance of a function.
class FuncInfo {
public:
	FuncInfo(ScriptFunc* _func, ScopePtr _scope, StmtPtr _body)
		{
		func = _func;
		scope = _scope;
		body = _body;
		pf = nullptr;
		}

	~FuncInfo();

	ScriptFunc* func;
	ScopePtr scope;
	StmtPtr body;
	ProfileFunc* pf;

	// If we're saving this function in a file, this is the name
	// of the file to use.
	char* save_file = nullptr;
};


#ifdef NOT_YET
// Whether we're in the midst of parsing a ZAM file.
extern bool in_ZAM_file;
#endif

// We track which functions are definitely not recursive.  We do this
// as the negative, rather than tracking functions known to be recursive,
// so that if we don't do the analysis at all (it's driven by inlining),
// we err on the conservative side and assume every function is recursive.
extern std::unordered_set<const Func*> non_recursive_funcs;

extern void analyze_func(ScriptFunc* f);
extern void analyze_scripts(Options& opts);
extern void finish_script_execution();


} // namespace zeek::detail
