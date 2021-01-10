// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Options.h"
#include "zeek/Reporter.h"
#include "zeek/Desc.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/Inline.h"
#include "zeek/script_opt/Reduce.h"


namespace zeek::detail {


std::unordered_set<const Func*> non_recursive_funcs;

// Tracks all of the loaded functions (including event handlers and hooks).
static std::vector<FuncInfo> funcs;


void optimize_func(ScriptFunc* f, ProfileFunc* pf, ScopePtr scope_ptr,
			StmtPtr& body, AnalyOpt& analysis_options)
	{
	if ( reporter->Errors() > 0 )
		return;

	if ( ! analysis_options.activate )
		return;

	if ( analysis_options.only_func &&
	     ! util::streq(f->Name(), analysis_options.only_func) )
		return;

	if ( analysis_options.only_func )
		printf("Original: %s\n", obj_desc(body.get()).c_str());

	if ( pf->NumWhenStmts() > 0 || pf->NumLambdas() > 0 )
		{
		if ( analysis_options.only_func )
			printf("Skipping analysis due to \"when\" statement or use of lambdas\n");
		return;
		}

	auto scope = scope_ptr.release();
	push_existing_scope(scope);

	auto rc = new Reducer(scope);
	auto new_body = rc->Reduce(body);

	if ( reporter->Errors() > 0 )
		{
		delete rc;
		pop_scope();
		return;
		}

	non_reduced_perp = nullptr;
	checking_reduction = true;
	if ( ! new_body->IsReduced(rc) )
		printf("Reduction inconsistency for %s: %s\n", f->Name(),
			obj_desc(non_reduced_perp).c_str());
	checking_reduction = false;

	if ( analysis_options.only_func || analysis_options.dump_xform )
		printf("Transformed: %s\n", obj_desc(new_body.get()).c_str());

	f->ReplaceBody(body, new_body);
	body = new_body;

	int new_frame_size =
		scope->Length() + rc->NumTemps() + rc->NumNewLocals();

	if ( new_frame_size > f->FrameSize() )
		f->SetFrameSize(new_frame_size);

	delete rc;

	pop_scope();
	}


FuncInfo::FuncInfo(ScriptFuncPtr _func, ScopePtr _scope, StmtPtr _body)
		: func(std::move(_func)), scope(std::move(_scope)), body(std::move(_body))
	{}

void FuncInfo::SetProfile(std::unique_ptr<ProfileFunc> _pf)
	{ pf = std::move(_pf); }

void analyze_func(ScriptFuncPtr f)
	{
	funcs.emplace_back(f, ScopePtr{NewRef{}, f->GetScope()}, f->CurrentBody());
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
		check_env_opt("ZEEK_DUMP_XFORM", analysis_options.dump_xform);
		check_env_opt("ZEEK_INLINE", analysis_options.inliner);
		check_env_opt("ZEEK_XFORM", analysis_options.activate);

		if ( ! analysis_options.only_func )
			analysis_options.only_func = getenv("ZEEK_ONLY");

		if ( analysis_options.only_func )
			analysis_options.activate = true;

		did_init = true;
		}

	if ( ! analysis_options.activate && ! analysis_options.inliner )
		return;

	// Now that everything's parsed and BiF's have been initialized,
	// profile the functions.
	std::unordered_map<const ScriptFunc*, const ProfileFunc*> func_profs;

	for ( auto& f : funcs )
		{
		f.SetProfile(std::make_unique<ProfileFunc>(true));
		f.Body()->Traverse(f.Profile());
		func_profs[f.Func()] = f.Profile();
		}

	// Figure out which functions either directly or indirectly
	// appear in "when" clauses.

	// Final set of functions involved in "when" clauses.
	std::unordered_set<const ScriptFunc*> when_funcs;

	// Which functions we still need to analyze.
	std::unordered_set<const ScriptFunc*> when_funcs_to_do;

	for ( auto& f : funcs )
		{
		if ( f.Profile()->WhenCalls().size() > 0 )
			{
			when_funcs.insert(f.Func());

			for ( auto& bf : f.Profile()->WhenCalls() )
				when_funcs_to_do.insert(bf);

#ifdef NOT_YET
			if ( analysis_options.report_uncompilable )
				{
				ODesc d;
				f.ScriptFunc()->AddLocation(&d);
				printf("%s cannot be compiled due to use of \"when\" statement (%s)\n",
					f.ScriptFunc()->Name(), d.Description());
				}
#endif	// NOT_YET
			}
		}

	// Set of new functions to put on to-do list.  Separate from
	// the to-do list itself so we don't modify it while iterating
	// over it.
	std::unordered_set<const ScriptFunc*> new_to_do;

	while ( when_funcs_to_do.size() > 0 )
		{
		for ( auto& wf : when_funcs_to_do )
			{
			when_funcs.insert(wf);

			for ( auto& wff : func_profs[wf]->ScriptCalls() )
				{
				if ( when_funcs.count(wff) > 0 )
					// We've already processed this
					// function.
					continue;

				new_to_do.insert(wff);
				}
			}

		when_funcs_to_do = new_to_do;
		new_to_do.clear();
		}

	Inliner* inl = nullptr;
	if ( analysis_options.inliner )
		inl = new Inliner(funcs, analysis_options.report_recursive);

	if ( ! analysis_options.activate )
		{
		delete inl;
		return;
		}

	for ( auto& f : funcs )
		{
		if ( inl && inl->WasInlined(f.Func()) )
			// No need to compile as it won't be
			// called directly.
			continue;

		if ( when_funcs.count(f.Func()) > 0 )
			// We don't try to compile these.
			continue;

		auto new_body = f.Body();
		optimize_func(f.Func(), f.Profile(), f.Scope(),
				new_body, analysis_options);
		f.SetBody(new_body);
		}

	delete inl;
	}


} // namespace zeek::detail
