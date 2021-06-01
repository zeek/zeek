// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Options.h"
#include "zeek/Reporter.h"
#include "zeek/module_util.h"
#include "zeek/Desc.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/Inline.h"
#include "zeek/script_opt/Reduce.h"
#include "zeek/script_opt/GenRDs.h"
#include "zeek/script_opt/UseDefs.h"
#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/CPP/Func.h"


namespace zeek::detail {


AnalyOpt analysis_options;

std::unordered_set<const Func*> non_recursive_funcs;

void (*CPP_init_hook)() = nullptr;

// Tracks all of the loaded functions (including event handlers and hooks).
static std::vector<FuncInfo> funcs;

static ZAMCompiler* ZAM = nullptr;


void optimize_func(ScriptFunc* f, std::shared_ptr<ProfileFunc> pf,
			ScopePtr scope, StmtPtr& body,
			AnalyOpt& analysis_options)
	{
	if ( reporter->Errors() > 0 )
		return;

	if ( ! analysis_options.activate )
		return;

	if ( analysis_options.only_func &&
	     *analysis_options.only_func != f->Name() )
		return;

	if ( analysis_options.only_func )
		printf("Original: %s\n", obj_desc(body.get()).c_str());

	if ( body->Tag() == STMT_CPP )
		// We're not able to optimize this.
		return;

	if ( pf->NumWhenStmts() > 0 || pf->NumLambdas() > 0 )
		{
		if ( analysis_options.only_func )
			printf("Skipping analysis due to \"when\" statement or use of lambdas\n");
		return;
		}

	push_existing_scope(scope);

	auto rc = std::make_shared<Reducer>();
	auto new_body = rc->Reduce(body);

	if ( reporter->Errors() > 0 )
		{
		pop_scope();
		return;
		}

	non_reduced_perp = nullptr;
	checking_reduction = true;

	if ( ! new_body->IsReduced(rc.get()) )
		{
		if ( non_reduced_perp )
			printf("Reduction inconsistency for %s: %s\n", f->Name(),
			       obj_desc(non_reduced_perp).c_str());
		else
			printf("Reduction inconsistency for %s\n", f->Name());
		}

	checking_reduction = false;

	if ( analysis_options.only_func || analysis_options.dump_xform )
		printf("Transformed: %s\n", obj_desc(new_body.get()).c_str());

	f->ReplaceBody(body, new_body);
	body = new_body;

	if ( analysis_options.optimize_AST )
		{
		pf = std::make_shared<ProfileFunc>(f, body, true);

		RD_Decorate reduced_rds(pf);
		reduced_rds.TraverseFunction(f, scope, body);

		if ( reporter->Errors() > 0 )
			{
			pop_scope();
			return;
			}

		rc->SetDefSetsMgr(reduced_rds.GetDefSetsMgr());

		new_body = rc->Reduce(body);

		if ( reporter->Errors() > 0 )
			{
			pop_scope();
			return;
			}

		if ( analysis_options.only_func || analysis_options.dump_xform )
			printf("Optimized: %s\n", obj_desc(new_body.get()).c_str());

		f->ReplaceBody(body, new_body);
		body = new_body;
		}

	// Profile the new body.
	pf = std::make_shared<ProfileFunc>(f, body, true);

	// Compute its reaching definitions.
	RD_Decorate reduced_rds(pf);

	reduced_rds.TraverseFunction(f, scope, body);

	rc->SetDefSetsMgr(reduced_rds.GetDefSetsMgr());

	auto ud = std::make_shared<UseDefs>(body, rc);
	ud->Analyze();

	if ( analysis_options.dump_uds )
		ud->Dump();

	new_body = ud->RemoveUnused();

	if ( new_body != body )
		{
		f->ReplaceBody(body, new_body);
		body = new_body;
		}

	int new_frame_size =
		scope->Length() + rc->NumTemps() + rc->NumNewLocals();

	if ( new_frame_size > f->FrameSize() )
		f->SetFrameSize(new_frame_size);

	pop_scope();
	}


FuncInfo::FuncInfo(ScriptFuncPtr _func, ScopePtr _scope, StmtPtr _body,
                   int _priority)
		: func(std::move(_func)), scope(std::move(_scope)),
		  body(std::move(_body)), priority(_priority)
	{}

void FuncInfo::SetProfile(std::shared_ptr<ProfileFunc> _pf)
	{ pf = std::move(_pf); }

void analyze_func(ScriptFuncPtr f)
	{
	if ( analysis_options.only_func &&
	     *analysis_options.only_func != f->Name() )
		return;

	funcs.emplace_back(f, f->GetScope(), f->CurrentBody(),
	                   f->CurrentPriority());
	}

const FuncInfo* analyze_global_stmts(Stmt* stmts)
	{
	// We ignore analysis_options.only_func - if it's in use, later
	// logic will keep this function from being compiled, but it's handy
	// now to enter it into "funcs" so we have a FuncInfo to return.

	auto id = install_ID("<global-stmts>", GLOBAL_MODULE_NAME, true, false);
	auto empty_args_t = make_intrusive<RecordType>(nullptr);
	auto func_t = make_intrusive<FuncType>(empty_args_t, nullptr, FUNC_FLAVOR_FUNCTION);
	id->SetType(func_t);

	auto sc = current_scope();
	std::vector<IDPtr> empty_inits;
	StmtPtr stmts_p{NewRef{}, stmts};
	auto sf = make_intrusive<ScriptFunc>(id, stmts_p, empty_inits, sc->Length(), 0);

	funcs.emplace_back(sf, sc, stmts_p, 0);

	return &funcs.back();
	}

static void check_env_opt(const char* opt, bool& opt_flag)
	{
	if ( getenv(opt) )
		opt_flag = true;
	}

void analyze_scripts()
	{
	static bool did_init = false;
	static std::string hash_dir;

	bool generating_CPP = false;

	if ( ! did_init )
		{
		auto hd = getenv("ZEEK_HASH_DIR");
		if ( hd )
			hash_dir = std::string(hd) + "/";

		check_env_opt("ZEEK_DUMP_XFORM", analysis_options.dump_xform);
		check_env_opt("ZEEK_DUMP_UDS", analysis_options.dump_uds);
		check_env_opt("ZEEK_INLINE", analysis_options.inliner);
		check_env_opt("ZEEK_OPT", analysis_options.optimize_AST);
		check_env_opt("ZEEK_XFORM", analysis_options.activate);
		check_env_opt("ZEEK_ADD_CPP", analysis_options.add_CPP);
		check_env_opt("ZEEK_UPDATE_CPP", analysis_options.update_CPP);
		check_env_opt("ZEEK_GEN_CPP", analysis_options.gen_CPP);
		check_env_opt("ZEEK_GEN_STANDALONE_CPP",
		              analysis_options.gen_standalone_CPP);
		check_env_opt("ZEEK_COMPILE_ALL", analysis_options.compile_all);
		check_env_opt("ZEEK_REPORT_CPP", analysis_options.report_CPP);
		check_env_opt("ZEEK_USE_CPP", analysis_options.use_CPP);

		if ( analysis_options.gen_standalone_CPP )
			analysis_options.gen_CPP = true;

		if ( analysis_options.gen_CPP )
			{
			if ( analysis_options.add_CPP )
				{
				reporter->Warning("gen-C++ incompatible with add-C++");
				analysis_options.add_CPP = false;
				}

			if ( analysis_options.update_CPP )
				{
				reporter->Warning("gen-C++ incompatible with update-C++");
				analysis_options.update_CPP = false;
				}

			generating_CPP = true;
			}

		if ( analysis_options.update_CPP || analysis_options.add_CPP )
			generating_CPP = true;

		if ( analysis_options.use_CPP && generating_CPP )
			{
			reporter->Error("generating C++ incompatible with using C++");
			exit(1);
			}

		if ( analysis_options.use_CPP && ! CPP_init_hook )
			{
			reporter->Error("no C++ functions available to use");
			exit(1);
			}

		auto usage = getenv("ZEEK_USAGE_ISSUES");

		if ( usage )
			analysis_options.usage_issues = atoi(usage) > 1 ? 2 : 1;

		if ( ! analysis_options.only_func )
			{
			auto zo = getenv("ZEEK_ONLY");
			if ( zo )
				analysis_options.only_func = zo;
			}

		if ( analysis_options.only_func ||
		     analysis_options.optimize_AST ||
		     analysis_options.usage_issues > 0 )
			analysis_options.activate = true;

		did_init = true;
		}

	if ( ! analysis_options.activate && ! analysis_options.inliner &&
	     ! generating_CPP && ! analysis_options.report_CPP &&
	     ! analysis_options.use_CPP )
		// Avoid profiling overhead.
		return;

	const auto hash_name = hash_dir + "CPP-hashes";
	const auto gen_name = hash_dir + "CPP-gen-addl.h";

	// Now that everything's parsed and BiF's have been initialized,
	// profile the functions.
	auto pfs = std::make_unique<ProfileFuncs>(funcs, is_CPP_compilable, false);

	if ( CPP_init_hook )
		(*CPP_init_hook)();

	if ( analysis_options.report_CPP )
		{
		if ( ! CPP_init_hook )
			{
			printf("no C++ script bodies available\n");
			exit(0);
			}

		printf("C++ script bodies available that match loaded scripts:\n");

		std::unordered_set<unsigned long long> already_reported;

		for ( auto& f : funcs )
			{
			auto name = f.Func()->Name();
			auto hash = f.Profile()->HashVal();
			bool have = compiled_scripts.count(hash) > 0;
			auto specific = "";

			if ( ! have )
				{
				hash = script_specific_hash(f.Body(), hash);
				have = compiled_scripts.count(hash) > 0;
				if ( have )
					specific = " - specific";
				}

			printf("script function %s (hash %llu%s): %s\n",
				name, hash, specific, have ? "yes" : "no");

			if ( have )
				already_reported.insert(hash);
			}

		printf("\nAdditional C++ script bodies available:\n");
		int addl = 0;
		for ( const auto& s : compiled_scripts )
			if ( already_reported.count(s.first) == 0 )
				{
				printf("%s body (hash %llu)\n",
					s.second.body->Name().c_str(), s.first);
				++addl;
				}

		if ( addl == 0 )
			printf("(none)\n");

		exit(0);
		}

	if ( analysis_options.use_CPP )
		{
		for ( auto& f : funcs )
			{
			auto hash = f.Profile()->HashVal();
			auto s = compiled_scripts.find(hash);

			if ( s == compiled_scripts.end() )
				{ // Look for script-specific body.
				hash = script_specific_hash(f.Body(), hash);
				s = compiled_scripts.find(hash);
				}

			if ( s != compiled_scripts.end() )
				{
				auto b = s->second.body;
				b->SetHash(hash);
				f.Func()->ReplaceBody(f.Body(), b);
				f.SetBody(b);

				for ( auto& e : s->second.events )
					{
					auto h = event_registry->Register(e);
					h->SetUsed();
					}
				}
			}

		// Now that we've loaded all of the compiled scripts
		// relevant for the AST, activate standalone ones.
		for ( auto cb : standalone_activations )
			(*cb)();
		}

	if ( generating_CPP )
		{
		auto hm = std::make_unique<CPPHashManager>(hash_name.c_str(),
						analysis_options.add_CPP);

		if ( ! analysis_options.gen_CPP )
			{
			for ( auto& func : funcs )
				{
				auto hash = func.Profile()->HashVal();
				if ( compiled_scripts.count(hash) > 0 ||
				     hm->HasHash(hash) )
					func.SetSkip(true);
				}

			// Now that we've presumably marked a lot of functions
			// as skippable, recompute the global profile.
			pfs = std::make_unique<ProfileFuncs>(funcs, is_CPP_compilable, false);
			}

		CPPCompile cpp(funcs, *pfs, gen_name.c_str(), *hm,
			       analysis_options.gen_CPP ||
			       analysis_options.update_CPP,
			       analysis_options.gen_standalone_CPP);

		exit(0);
		}

	if ( analysis_options.usage_issues > 0 && analysis_options.optimize_AST )
		{
		fprintf(stderr, "warning: \"-O optimize-AST\" option is incompatible with -u option, deactivating optimization\n");
		analysis_options.optimize_AST = false;
		}

	// Re-profile the functions, this time without worrying about
	// compatibility with compilation to C++.  Note that the first
	// profiling pass above may have marked some of the functions
	// as to-skip, so first clear those markings.  Once we have
	// full compile-to-C++ and ZAM support for all Zeek language
	// features, we can remove the re-profiling here.
	for ( auto& f : funcs )
		f.SetSkip(false);

	pfs = std::make_unique<ProfileFuncs>(funcs, nullptr, true);

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
				{
				ASSERT(pfs->FuncProf(bf));
				when_funcs_to_do.insert(bf);
				}

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

			for ( auto& wff : pfs->FuncProf(wf)->ScriptCalls() )
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

	std::unique_ptr<Inliner> inl;
	if ( analysis_options.inliner )
		inl = std::make_unique<Inliner>(funcs, analysis_options.report_recursive);

	if ( ! analysis_options.activate )
		return;

	// The following tracks inlined functions that are also used
	// indirectly, and thus should be compiled even if they were
	// inlined.  We don't bother populating this if we're not inlining,
	// since it won't be consulted in that case.
	std::unordered_set<Func*> func_used_indirectly;

	if ( inl )
		{
		for ( auto& f : funcs )
			{
			for ( const auto& g : f.Profile()->Globals() )
				{
				if ( g->GetType()->Tag() != TYPE_FUNC )
					continue;

				auto v = g->GetVal();
				if ( ! v )
					continue;

				auto func = v->AsFunc();

				if ( inl->WasInlined(func) )
					func_used_indirectly.insert(func);
				}
			}
		}

	for ( auto& f : funcs )
		{
		auto func = f.Func();

		if ( ! analysis_options.compile_all &&
		     inl && inl->WasInlined(func) &&
		     func_used_indirectly.count(func) == 0 )
			// No need to compile as it won't be
			// called directly.
			continue;

		if ( when_funcs.count(func) > 0 )
			// We don't try to compile these.
			continue;

		auto new_body = f.Body();
		optimize_func(func, f.ProfilePtr(), f.Scope(), new_body,
		              analysis_options);
		f.SetBody(new_body);
		}
	}


} // namespace zeek::detail
