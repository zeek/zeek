// See the file "COPYING" in the main distribution directory for copyright.

// Options that control script analysis/optimization.

#pragma once

#include <optional>
#include <regex>
#include <string>

namespace zeek::detail
	{

struct AnalyOpt
	{
	// Options applicable across multiple types of script optimization.

	// If non-nil, then only analyze function/event/hook(s) whose names
	// match one of the given regular expressions.
	//
	// Applies to both ZAM and C++.
	std::vector<std::regex> only_funcs;

	// Same, but for the filenames where the function is found.
	std::vector<std::regex> only_files;

	// For a given compilation target, report functions that can't
	// be compiled.
	bool report_uncompilable = false;

	////// Options relating to ZAM:

	// Whether to analyze scripts.
	bool activate = false;

	// If true, compile all compilable functions, even those that
	// are inlined.  Mainly useful for ensuring compatibility for
	// some tests in the test suite.
	bool compile_all = false;

	// Whether to optimize the AST.
	bool optimize_AST = false;

	// If true, do global inlining.
	bool inliner = false;

	// If true, report which functions are directly and indirectly
	// recursive, and exit.  Only germane if running the inliner.
	bool report_recursive = false;

	// If true, generate ZAM code for applicable function bodies,
	// activating all optimizations.
	bool gen_ZAM = false;

	// Generate ZAM code, but do not turn on optimizations unless
	// specified.
	bool gen_ZAM_code = false;

	// Deactivate the low-level ZAM optimizer.
	bool no_ZAM_opt = false;

	// Reduce memory footprint by diminishing some diagnostics.
	bool reduce_memory = false;

	// Produce a profile of ZAM execution.
	bool profile_ZAM = false;

	// If true, dump out transformed code: the results of reducing
	// interpreted scripts, and, if optimize is set, of then optimizing
	// them.
	bool dump_xform = false;

	// If true, dump out the use-defs for each analyzed function.
	bool dump_uds = false;

	// If true, dump out generated ZAM code.
	bool dump_ZAM = false;

	// If non-zero, looks for variables that are used-but-possibly-not-set,
	// or set-but-not-used.  We store this as an int rather than a bool
	// because we might at some point extend the analysis to deeper forms
	// of usage issues, such as those present in record fields.
	//
	// Included here with other ZAM-related options since conducting
	// the analysis requires activating some of the machinery used
	// for ZAM.
	int usage_issues = 0;

	////// Options relating to C++:

	// If true, generate C++;
	bool gen_CPP = false;

	// If true, the C++ should be standalone (not require the presence
	// of the corresponding script, and not activated by default).
	bool gen_standalone_CPP = false;

	// If true, use C++ bodies if available.
	bool use_CPP = false;

	// If true, report on available C++ bodies.
	bool report_CPP = false;

	// If true, allow standalone compilation in the presence of
	// conditional code.
	bool allow_cond = false;
	};

extern AnalyOpt analysis_options;

	} // namespace zeek::detail
