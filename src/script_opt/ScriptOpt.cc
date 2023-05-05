// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ScriptOpt.h"

#include "zeek/Desc.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/Options.h"
#include "zeek/Reporter.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/CPP/Func.h"
#include "zeek/script_opt/GenIDDefs.h"
#include "zeek/script_opt/Inline.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/Reduce.h"
#include "zeek/script_opt/UsageAnalyzer.h"
#include "zeek/script_opt/UseDefs.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail
	{

AnalyOpt analysis_options;

std::unordered_set<const Func*> non_recursive_funcs;

void (*CPP_init_hook)() = nullptr;
void (*CPP_activation_hook)() = nullptr;

// Tracks all of the loaded functions (including event handlers and hooks).
static std::vector<FuncInfo> funcs;

static ZAMCompiler* ZAM = nullptr;

static bool generating_CPP = false;
static std::string CPP_dir; // where to generate C++ code

static ScriptFuncPtr global_stmts;

void analyze_func(ScriptFuncPtr f)
	{
	// Even if we're analyzing only a subset of the scripts, we still
	// track all functions here because the inliner will need the full list.
	funcs.emplace_back(f, f->GetScope(), f->CurrentBody(), f->CurrentPriority());
	}

const FuncInfo* analyze_global_stmts(Stmt* stmts)
	{
	// We ignore analysis_options.only_{files,funcs} - if they're in use, later
	// logic will keep this function from being compiled, but it's handy
	// now to enter it into "funcs" so we have a FuncInfo to return.

	auto id = install_ID("<global-stmts>", GLOBAL_MODULE_NAME, true, false);
	auto empty_args_t = make_intrusive<RecordType>(nullptr);
	auto func_t = make_intrusive<FuncType>(empty_args_t, nullptr, FUNC_FLAVOR_FUNCTION);
	id->SetType(func_t);

	auto sc = current_scope();
	std::vector<IDPtr> empty_inits;
	StmtPtr stmts_p{NewRef{}, stmts};
	global_stmts = make_intrusive<ScriptFunc>(id);
	global_stmts->AddBody(stmts_p, empty_inits, sc->Length());

	funcs.emplace_back(global_stmts, sc, stmts_p, 0);

	return &funcs.back();
	}

void add_func_analysis_pattern(AnalyOpt& opts, const char* pat)
	{
	try
		{
		std::string full_pat = std::string("^(") + pat + ")$";
		opts.only_funcs.emplace_back(std::regex(full_pat));
		}
	catch ( const std::regex_error& e )
		{
		reporter->FatalError("bad file analysis pattern: %s", pat);
		}
	}

void add_file_analysis_pattern(AnalyOpt& opts, const char* pat)
	{
	try
		{
		std::string full_pat = std::string("^.*(") + pat + ").*$";
		opts.only_files.emplace_back(std::regex(full_pat));
		}
	catch ( const std::regex_error& e )
		{
		reporter->FatalError("bad file analysis pattern: %s", pat);
		}
	}

bool should_analyze(const ScriptFuncPtr& f, const StmtPtr& body)
	{
	auto& ofuncs = analysis_options.only_funcs;
	auto& ofiles = analysis_options.only_files;

	if ( ofiles.empty() && ofuncs.empty() )
		return true;

	auto fun = f->Name();

	for ( auto& o : ofuncs )
		if ( std::regex_match(fun, o) )
			return true;

	auto fin = util::detail::normalize_path(body->GetLocationInfo()->filename);

	for ( auto& o : ofiles )
		if ( std::regex_match(fin, o) )
			return true;

	return false;
	}

static bool optimize_AST(ScriptFunc* f, std::shared_ptr<ProfileFunc>& pf,
                         std::shared_ptr<Reducer>& rc, ScopePtr scope, StmtPtr& body)
	{
	pf = std::make_shared<ProfileFunc>(f, body, true);

	GenIDDefs ID_defs(pf, f, scope, body);

	if ( reporter->Errors() > 0 )
		return false;

	rc->SetReadyToOptimize();

	auto new_body = rc->Reduce(body);

	if ( reporter->Errors() > 0 )
		return false;

	if ( analysis_options.dump_xform )
		printf("Optimized: %s\n", obj_desc(new_body.get()).c_str());

	f->ReplaceBody(body, new_body);
	body = new_body;

	return true;
	}

static void optimize_func(ScriptFunc* f, std::shared_ptr<ProfileFunc> pf, ScopePtr scope,
                          StmtPtr& body)
	{
	if ( reporter->Errors() > 0 )
		return;

	if ( analysis_options.dump_xform )
		printf("Original: %s\n", obj_desc(body.get()).c_str());

	if ( body->Tag() == STMT_CPP )
		// We're not able to optimize this.
		return;

	const char* reason;
	if ( ! is_ZAM_compilable(pf.get(), &reason) )
		{
		if ( analysis_options.report_uncompilable )
			printf("Skipping compilation of %s due to %s\n", f->Name(), reason);
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
			reporter->InternalError("Reduction inconsistency for %s: %s\n", f->Name(),
			                        obj_desc(non_reduced_perp).c_str());
		else
			reporter->InternalError("Reduction inconsistency for %s\n", f->Name());
		}

	checking_reduction = false;

	if ( analysis_options.dump_xform )
		printf("Transformed: %s\n", obj_desc(new_body.get()).c_str());

	f->ReplaceBody(body, new_body);
	body = new_body;

	if ( analysis_options.optimize_AST && ! optimize_AST(f, pf, rc, scope, body) )
		{
		pop_scope();
		return;
		}

	// Profile the new body.
	pf = std::make_shared<ProfileFunc>(f, body, true);

	// Compute its reaching definitions.
	GenIDDefs ID_defs(pf, f, scope, body);

	rc->SetReadyToOptimize();

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

	int new_frame_size = scope->Length() + rc->NumTemps() + rc->NumNewLocals();

	if ( new_frame_size > f->FrameSize() )
		f->SetFrameSize(new_frame_size);

	if ( analysis_options.gen_ZAM_code )
		{
		ZAM = new ZAMCompiler(f, pf, scope, new_body, ud, rc);

		new_body = ZAM->CompileBody();

		if ( reporter->Errors() > 0 )
			return;

		if ( analysis_options.dump_ZAM )
			ZAM->Dump();

		f->ReplaceBody(body, new_body);
		body = new_body;
		}

	pop_scope();
	}

static void check_env_opt(const char* opt, bool& opt_flag)
	{
	if ( getenv(opt) )
		opt_flag = true;
	}

static void init_options()
	{
	auto cppd = getenv("ZEEK_CPP_DIR");
	if ( cppd )
		CPP_dir = std::string(cppd) + "/";

	// ZAM-related options.
	check_env_opt("ZEEK_DUMP_XFORM", analysis_options.dump_xform);
	check_env_opt("ZEEK_DUMP_UDS", analysis_options.dump_uds);
	check_env_opt("ZEEK_INLINE", analysis_options.inliner);
	check_env_opt("ZEEK_OPT", analysis_options.optimize_AST);
	check_env_opt("ZEEK_XFORM", analysis_options.activate);
	check_env_opt("ZEEK_ZAM", analysis_options.gen_ZAM);
	check_env_opt("ZEEK_COMPILE_ALL", analysis_options.compile_all);
	check_env_opt("ZEEK_REPORT_UNCOMPILABLE", analysis_options.report_uncompilable);
	check_env_opt("ZEEK_ZAM_CODE", analysis_options.gen_ZAM_code);
	check_env_opt("ZEEK_NO_ZAM_OPT", analysis_options.no_ZAM_opt);
	check_env_opt("ZEEK_DUMP_ZAM", analysis_options.dump_ZAM);
	check_env_opt("ZEEK_PROFILE", analysis_options.profile_ZAM);

	// Compile-to-C++-related options.
	check_env_opt("ZEEK_GEN_CPP", analysis_options.gen_CPP);
	check_env_opt("ZEEK_GEN_STANDALONE_CPP", analysis_options.gen_standalone_CPP);
	check_env_opt("ZEEK_COMPILE_ALL", analysis_options.compile_all);
	check_env_opt("ZEEK_REPORT_CPP", analysis_options.report_CPP);
	check_env_opt("ZEEK_USE_CPP", analysis_options.use_CPP);
	check_env_opt("ZEEK_ALLOW_COND", analysis_options.allow_cond);

	if ( analysis_options.gen_standalone_CPP )
		analysis_options.gen_CPP = true;

	if ( analysis_options.gen_CPP )
		generating_CPP = true;

	if ( analysis_options.use_CPP && generating_CPP )
		reporter->FatalError("generating C++ incompatible with using C++");

	if ( analysis_options.allow_cond && ! analysis_options.gen_standalone_CPP )
		reporter->FatalError(
			"\"-O allow-cond\" only relevant when also using \"-O gen-standalone-C++\"");

	auto usage = getenv("ZEEK_USAGE_ISSUES");

	if ( usage )
		analysis_options.usage_issues = 1;

	if ( analysis_options.only_funcs.empty() )
		{
		auto zo = getenv("ZEEK_OPT_FUNCS");
		if ( zo )
			add_func_analysis_pattern(analysis_options, zo);
		}

	if ( analysis_options.only_files.empty() )
		{
		auto zo = getenv("ZEEK_OPT_FILES");
		if ( zo )
			add_file_analysis_pattern(analysis_options, zo);
		}

	if ( analysis_options.gen_ZAM )
		{
		analysis_options.gen_ZAM_code = true;
		analysis_options.inliner = true;
		analysis_options.optimize_AST = true;
		}

	if ( analysis_options.dump_ZAM )
		analysis_options.gen_ZAM_code = true;

	if ( ! analysis_options.only_funcs.empty() || ! analysis_options.only_files.empty() )
		{
		if ( analysis_options.gen_ZAM_code || generating_CPP )
			analysis_options.report_uncompilable = true;
		}

	if ( analysis_options.report_uncompilable && ! analysis_options.gen_ZAM_code &&
	     ! generating_CPP )
		reporter->FatalError("report-uncompilable requires generation of ZAM or C++");

	if ( analysis_options.optimize_AST || analysis_options.gen_ZAM_code ||
	     analysis_options.usage_issues > 0 )
		analysis_options.activate = true;
	}

static void report_CPP()
	{
	if ( ! CPP_init_hook )
		reporter->FatalError("no C++ script bodies available");

	printf("C++ script bodies available that match loaded scripts:\n");

	std::unordered_set<unsigned long long> already_reported;

	for ( auto& f : funcs )
		{
		auto name = f.Func()->Name();
		auto hash = f.Profile()->HashVal();
		bool have = compiled_scripts.count(hash) > 0;

		printf("script function %s (hash %llu): %s\n", name, hash, have ? "yes" : "no");

		if ( have )
			already_reported.insert(hash);
		}

	printf("\nAdditional C++ script bodies available:\n");

	int addl = 0;
	for ( const auto& s : compiled_scripts )
		if ( already_reported.count(s.first) == 0 )
			{
			printf("%s body (hash %llu)\n", s.second.body->Name().c_str(), s.first);
			++addl;
			}

	if ( addl == 0 )
		printf("(none)\n");
	}

static void use_CPP()
	{
	if ( ! CPP_init_hook )
		reporter->FatalError("no C++ functions available to use");

	int num_used = 0;

	for ( auto& f : funcs )
		{
		auto hash = f.Profile()->HashVal();
		auto s = compiled_scripts.find(hash);

		if ( s != compiled_scripts.end() )
			{
			++num_used;

			auto b = s->second.body;
			b->SetHash(hash);

			// We may have already updated the body if
			// we're using code compiled for standalone.
			if ( f.Body()->Tag() != STMT_CPP )
				{
				auto func = f.Func();
				if ( added_bodies[func->Name()].count(hash) > 0 )
					// We've already added the
					// replacement.  Delete orig.
					func->ReplaceBody(f.Body(), nullptr);
				else
					func->ReplaceBody(f.Body(), b);

				f.SetBody(b);
				}

			for ( auto& e : s->second.events )
				{
				auto h = event_registry->Register(e);
				h->SetUsed();
				}

			auto finish = s->second.finish_init_func;
			if ( finish )
				(*finish)();
			}
		}

	if ( num_used == 0 )
		reporter->FatalError("no C++ functions found to use");
	}

static void generate_CPP(std::unique_ptr<ProfileFuncs>& pfs)
	{
	const auto gen_name = CPP_dir + "CPP-gen.cc";

	const bool standalone = analysis_options.gen_standalone_CPP;
	const bool report = analysis_options.report_uncompilable;

	CPPCompile cpp(funcs, *pfs, gen_name, standalone, report);
	}

static void analyze_scripts_for_ZAM(std::unique_ptr<ProfileFuncs>& pfs)
	{
	if ( analysis_options.usage_issues > 0 && analysis_options.optimize_AST )
		{
		fprintf(stderr, "warning: \"-O optimize-AST\" option is incompatible with -u option, "
		                "deactivating optimization\n");
		analysis_options.optimize_AST = false;
		}

	// Re-profile the functions, now without worrying about compatibility
	// with compilation to C++.  Note that the first profiling pass earlier
	// may have marked some of the functions as to-skip, so first clear
	// those markings.  Once we have full compile-to-C++ and ZAM support
	// for all Zeek language features, we can remove the re-profiling here.
	for ( auto& f : funcs )
		f.SetSkip(false);

	pfs = std::make_unique<ProfileFuncs>(funcs, nullptr, true);

	bool report_recursive = analysis_options.report_recursive;
	std::unique_ptr<Inliner> inl;
	if ( analysis_options.inliner )
		inl = std::make_unique<Inliner>(funcs, report_recursive);

	if ( ! analysis_options.activate )
		// Some --optimize options stop short of AST transformations,
		// for development/debugging purposes.
		return;

	// The following tracks inlined functions that are also used
	// indirectly, and thus should be compiled even if they were
	// inlined.  We don't bother populating this if we're not inlining,
	// since it won't be consulted in that case.
	std::unordered_set<Func*> func_used_indirectly;

	if ( global_stmts )
		func_used_indirectly.insert(global_stmts.get());

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

	bool did_one = false;

	for ( auto& f : funcs )
		{
		auto func = f.Func();

		if ( ! analysis_options.only_funcs.empty() || ! analysis_options.only_files.empty() )
			{
			if ( ! should_analyze(f.FuncPtr(), f.Body()) )
				continue;
			}

		else if ( ! analysis_options.compile_all && inl && inl->WasInlined(func) &&
		          func_used_indirectly.count(func) == 0 )
			// No need to compile as it won't be called directly.
			continue;

		auto new_body = f.Body();
		optimize_func(func, f.ProfilePtr(), f.Scope(), new_body);
		f.SetBody(new_body);
		did_one = true;
		}

	if ( ! did_one )
		reporter->FatalError("no matching functions/files for -O ZAM");

	finalize_functions(funcs);
	}

void analyze_scripts(bool no_unused_warnings)
	{
	init_options();

	// Any standalone compiled scripts have already been instantiated
	// at this point, but may require post-loading-of-scripts finalization.
	for ( auto cb : standalone_finalizations )
		(*cb)();

	std::unique_ptr<UsageAnalyzer> ua;
	if ( ! no_unused_warnings )
		ua = std::make_unique<UsageAnalyzer>(funcs);

	auto& ofuncs = analysis_options.only_funcs;
	auto& ofiles = analysis_options.only_files;

	if ( ! analysis_options.activate && ! analysis_options.inliner && ! generating_CPP &&
	     ! analysis_options.report_CPP && ! analysis_options.use_CPP )
		{ // No work to do, avoid profiling overhead.
		if ( ! ofuncs.empty() )
			reporter->FatalError("--optimize-funcs used but no optimization specified");
		if ( ! ofiles.empty() )
			reporter->FatalError("--optimize-files used but no optimization specified");

		return;
		}

	bool have_one_to_do = false;

	for ( auto& func : funcs )
		if ( should_analyze(func.FuncPtr(), func.Body()) )
			have_one_to_do = true;
		else
			func.SetSkip(true);

	if ( ! have_one_to_do )
		reporter->FatalError("no matching functions/files for C++ compilation");

	// Now that everything's parsed and BiF's have been initialized,
	// profile the functions.
	auto pfs = std::make_unique<ProfileFuncs>(funcs, is_CPP_compilable, false);

	if ( CPP_init_hook )
		{
		(*CPP_init_hook)();
		if ( compiled_scripts.empty() )
			// The initialization failed to produce any
			// script bodies.  Make this easily available
			// to subsequent checks.
			CPP_init_hook = nullptr;
		}

	if ( analysis_options.report_CPP )
		{
		report_CPP();
		exit(0);
		}

	if ( analysis_options.use_CPP )
		use_CPP();

	if ( generating_CPP )
		{
		if ( analysis_options.gen_ZAM )
			reporter->FatalError("-O ZAM and -O gen-C++ conflict");

		generate_CPP(pfs);
		exit(0);
		}

	// At this point we're done with C++ considerations, so instead
	// are compiling to ZAM.
	analyze_scripts_for_ZAM(pfs);
	}

void profile_script_execution()
	{
	if ( analysis_options.profile_ZAM )
		{
		report_ZOP_profile();

		for ( auto& f : funcs )
			{
			if ( f.Body()->Tag() == STMT_ZAM )
				cast_intrusive<ZBody>(f.Body())->ProfileExecution();
			}
		}
	}

void finish_script_execution()
	{
	profile_script_execution();
	}

	} // namespace zeek::detail
