// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ScriptOpt.h"

#include "zeek/Options.h"
#include "zeek/script_opt/Inline.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail
{

std::unordered_set<const Func*> non_recursive_funcs;

// Tracks all of the loaded functions (including event handlers and hooks).
static std::vector<FuncInfo> funcs;

FuncInfo::FuncInfo(ScriptFuncPtr _func, ScopePtr _scope, StmtPtr _body)
	: func(std::move(_func)), scope(std::move(_scope)), body(std::move(_body))
	{
	}

void FuncInfo::SetProfile(std::unique_ptr<ProfileFunc> _pf)
	{
	pf = std::move(_pf);
	}

void analyze_func(ScriptFuncPtr f)
	{
	funcs.emplace_back(f, ScopePtr {NewRef {}, f->GetScope()}, f->CurrentBody());
	}

static void check_env_opt(const char* opt, bool& opt_flag)
	{
	if ( getenv(opt) )
		opt_flag = true;
	}

void analyze_scripts(Options& opts)
	{
	auto& analysis_options = opts.analysis_options;

	static bool did_init = false;

	if ( ! did_init )
		{
		check_env_opt("ZEEK_INLINE", analysis_options.inliner);
		did_init = true;
		}

	if ( ! analysis_options.inliner )
		return;

	for ( auto& f : funcs )
		{
		f.SetProfile(std::make_unique<ProfileFunc>(true));
		f.Body()->Traverse(f.Profile());
		}

	Inliner* inl = nullptr;
	if ( analysis_options.inliner )
		inl = new Inliner(funcs, analysis_options.report_recursive);

	delete inl;
	}

} // namespace zeek::detail
