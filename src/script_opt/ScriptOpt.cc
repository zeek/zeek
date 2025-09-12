// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ScriptOpt.h"

#include "zeek/Desc.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
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
#include "zeek/script_opt/ZAM/Profile.h"

namespace zeek::detail {

AnalyOpt analysis_options;

std::unordered_set<const Func*> non_recursive_funcs;

void (*CPP_init_hook)() = nullptr;

// Tracks all of the loaded functions (including event handlers and hooks).
static std::vector<FuncInfo> funcs;

static bool generating_CPP = false;
static std::string CPP_dir; // where to generate C++ code

static std::unordered_map<const ScriptFunc*, LambdaExpr*> lambdas;
static std::unordered_set<const ScriptFunc*> when_lambdas;
static ScriptFuncPtr global_stmts;
static size_t global_stmts_ind; // index into Funcs corresponding to global_stmts

void analyze_func(ScriptFuncPtr f) {
    // Even if we're analyzing only a subset of the scripts, we still
    // track all functions here because the inliner will need the full list.
    ASSERT(f->GetScope());
    funcs.emplace_back(f, f->GetScope(), f->CurrentBody(), f->CurrentPriority());
}

void analyze_lambda(LambdaExpr* l) {
    auto& pf = l->PrimaryFunc();
    analyze_func(pf);
    lambdas[pf.get()] = l;
}

void analyze_when_lambda(LambdaExpr* l) { when_lambdas.insert(l->PrimaryFunc().get()); }

bool is_lambda(const ScriptFunc* f) { return lambdas.contains(f); }

bool is_when_lambda(const ScriptFunc* f) { return when_lambdas.contains(f); }

void analyze_global_stmts(Stmt* stmts) {
    if ( analysis_options.gen_standalone_CPP && obj_matches_opt_files(stmts) == AnalyzeDecision::SHOULD )
        reporter->FatalError("cannot include global statements with -O gen-standalone-C++: %s",
                             obj_desc(stmts).c_str());

    // We ignore analysis_options.only_{files,funcs} - if they're in use, later
    // logic will keep this function from being compiled, but it's handy
    // now to enter it into "funcs" so we have a FuncInfo to return.

    auto id = install_ID("<global-stmts>", GLOBAL_MODULE_NAME, true, false);
    auto empty_args_t = make_intrusive<RecordType>(nullptr);
    auto func_t = make_intrusive<FuncType>(empty_args_t, nullptr, FUNC_FLAVOR_FUNCTION);
    func_t->SetName("<global-stmts>");
    id->SetType(func_t);

    auto sc = current_scope();
    std::vector<IDPtr> empty_inits;
    global_stmts = make_intrusive<ScriptFunc>(id);
    global_stmts->AddBody(stmts->ThisPtr(), empty_inits, sc->Length());
    global_stmts->SetScope(sc);

    global_stmts_ind = funcs.size();
    funcs.emplace_back(global_stmts, sc, stmts->ThisPtr(), 0);
}

std::pair<StmtPtr, ScopePtr> get_global_stmts() {
    ASSERT(global_stmts);
    auto& fi = funcs[global_stmts_ind];
    return std::pair<StmtPtr, ScopePtr>{fi.Body(), fi.Scope()};
}

void add_func_analysis_pattern(AnalyOpt& opts, const char* pat, bool is_only) {
    try {
        std::string full_pat = std::string("^(") + pat + ")$";
        if ( is_only )
            opts.only_funcs.emplace_back(full_pat);
        else
            opts.skip_funcs.emplace_back(full_pat);
    } catch ( const std::regex_error& e ) {
        reporter->FatalError("bad file analysis pattern: %s", pat);
    }
}

void add_file_analysis_pattern(AnalyOpt& opts, const char* pat, bool is_only) {
    try {
        std::string full_pat = std::string("^.*(") + pat + ").*$";
        if ( is_only )
            opts.only_files.emplace_back(full_pat);
        else
            opts.skip_files.emplace_back(full_pat);
    } catch ( const std::regex_error& e ) {
        reporter->FatalError("bad file analysis pattern: %s", pat);
    }
}

bool should_analyze(const ScriptFuncPtr& f, const StmtPtr& body) {
    auto& ofuncs = analysis_options.only_funcs;
    auto& sfuncs = analysis_options.skip_funcs;
    auto& ofiles = analysis_options.only_files;
    auto& sfiles = analysis_options.skip_files;

    bool have_onlies = ! ofiles.empty() || ! ofuncs.empty();

    if ( ! have_onlies && sfiles.empty() && sfuncs.empty() )
        // It's the default of compile-everything.
        return true;

    auto file_decision = obj_matches_opt_files(body.get());
    if ( file_decision == AnalyzeDecision::SHOULD_NOT )
        return false;

    // Even if the file decision is SHOULD, that can be overridden by
    // a function decision of "skip".

    const auto& fun = f->GetName();
    for ( auto& s : sfuncs )
        if ( std::regex_match(fun, s) )
            return false; // matches a "skip" function

    if ( file_decision == AnalyzeDecision::SHOULD )
        // It matches a specified file, and there's no "skip" for the function.
        return true;

    for ( auto& o : ofuncs )
        if ( std::regex_match(fun, o) )
            return true; // matches an "only" function

    // If we get here, neither the file nor the function has an "only"
    // or "skip" decision. If our sole directives were for skip's, then
    // we should analyze this function. If we have any only's, then we
    // shouldn't.
    return ! have_onlies;
}

AnalyzeDecision filename_matches_opt_files(const char* filename) {
    auto& ofiles = analysis_options.only_files;
    auto& sfiles = analysis_options.skip_files;

    if ( ofiles.empty() && sfiles.empty() )
        return AnalyzeDecision::DEFAULT;

    auto fin = util::detail::normalize_path(filename);

    for ( auto& s : analysis_options.skip_files )
        if ( std::regex_match(fin, s) )
            return AnalyzeDecision::SHOULD_NOT;

    for ( auto& o : ofiles )
        if ( std::regex_match(fin, o) )
            return AnalyzeDecision::SHOULD;

    return AnalyzeDecision::DEFAULT;
}

AnalyzeDecision obj_matches_opt_files(const Obj* obj) {
    return filename_matches_opt_files(obj->GetLocationInfo()->FileName());
}

static bool optimize_AST(ScriptFuncPtr f, std::shared_ptr<ProfileFunc>& pf, std::shared_ptr<Reducer>& rc,
                         ScopePtr scope, StmtPtr& body) {
    pf = std::make_shared<ProfileFunc>(f.get(), body, true);

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

static void optimize_func(ScriptFuncPtr f, std::shared_ptr<ProfileFunc> pf, std::shared_ptr<ProfileFuncs> pfs,
                          ScopePtr scope, StmtPtr& body) {
    if ( reporter->Errors() > 0 )
        return;

    if ( analysis_options.dump_xform )
        printf("Original: %s\n", obj_desc(body.get()).c_str());

    if ( body->Tag() == STMT_CPP )
        // We're not able to optimize this.
        return;

    const char* reason;
    if ( ! is_ZAM_compilable(pf.get(), &reason) ) {
        if ( analysis_options.report_uncompilable )
            printf("Skipping compilation of %s due to %s\n", f->GetName().c_str(), reason);
        return;
    }

    push_existing_scope(scope);

    auto rc = std::make_shared<Reducer>(f, pf, pfs);
    auto new_body = rc->Reduce(body);

    if ( reporter->Errors() > 0 ) {
        pop_scope();
        return;
    }

    non_reduced_perp = nullptr;
    checking_reduction = true;

    if ( ! new_body->IsReduced(rc.get()) ) {
        if ( non_reduced_perp )
            reporter->InternalError("Reduction inconsistency for %s: %s\n", f->GetName().c_str(),
                                    obj_desc(non_reduced_perp).c_str());
        else
            reporter->InternalError("Reduction inconsistency for %s\n", f->GetName().c_str());
    }

    checking_reduction = false;

    if ( analysis_options.dump_xform )
        printf("Transformed: %s\n", obj_desc(new_body.get()).c_str());

    f->ReplaceBody(body, new_body);
    body = new_body;

    if ( analysis_options.optimize_AST && ! optimize_AST(f, pf, rc, scope, body) ) {
        pop_scope();
        return;
    }

    // Profile the new body.
    pf = std::make_shared<ProfileFunc>(f.get(), body, true);

    // Compute its reaching definitions.
    GenIDDefs ID_defs(pf, f, scope, body);

    rc->SetReadyToOptimize();

    auto ft = cast_intrusive<FuncType>(f->GetType());
    auto ud = std::make_shared<UseDefs>(body, rc, ft);
    ud->Analyze();

    if ( analysis_options.dump_uds )
        ud->Dump();

    new_body = ud->RemoveUnused();

    if ( analysis_options.dump_xform )
        printf("Post removal of unused: %s\n", obj_desc(new_body.get()).c_str());

    if ( new_body != body ) {
        f->ReplaceBody(body, new_body);
        body = new_body;
    }

    int new_frame_size = scope->Length() + rc->NumTemps() + rc->NumNewLocals();

    if ( new_frame_size > f->FrameSize() )
        f->SetFrameSize(new_frame_size);

    if ( analysis_options.gen_ZAM_code ) {
        ZAMCompiler ZAM(f, pfs, pf, scope, new_body, ud, rc);

        new_body = ZAM.CompileBody();

        if ( reporter->Errors() > 0 )
            return;

        if ( analysis_options.dump_final_ZAM )
            ZAM.Dump();

        f->ReplaceBody(body, new_body);
        body = new_body;
    }

    pop_scope();
}

static void check_env_opt(const char* opt, bool& opt_flag) {
    if ( getenv(opt) )
        opt_flag = true;
}

static void init_options() {
    auto cppd = getenv("ZEEK_CPP_DIR");
    if ( cppd )
        CPP_dir = std::string(cppd) + "/";

    // ZAM-related options.
    check_env_opt("ZEEK_DUMP_XFORM", analysis_options.dump_xform);
    check_env_opt("ZEEK_DUMP_UDS", analysis_options.dump_uds);
    check_env_opt("ZEEK_INLINE", analysis_options.inliner);
    check_env_opt("ZEEK_NO_INLINE", analysis_options.no_inliner);
    check_env_opt("ZEEK_NO_EH_COALESCENCE", analysis_options.no_eh_coalescence);
    check_env_opt("ZEEK_OPT", analysis_options.optimize_AST);
    check_env_opt("ZEEK_XFORM", analysis_options.activate);
    check_env_opt("ZEEK_ZAM", analysis_options.gen_ZAM);
    check_env_opt("ZEEK_COMPILE_ALL", analysis_options.compile_all);
    check_env_opt("ZEEK_REPORT_UNCOMPILABLE", analysis_options.report_uncompilable);
    check_env_opt("ZEEK_ZAM_KEEP_ASSERTS", analysis_options.keep_asserts);
    check_env_opt("ZEEK_ZAM_CODE", analysis_options.gen_ZAM_code);
    check_env_opt("ZEEK_NO_ZAM_OPT", analysis_options.no_ZAM_opt);
    check_env_opt("ZEEK_NO_ZAM_CONTROL_FLOW_OPT", analysis_options.no_ZAM_control_flow_opt);
    check_env_opt("ZEEK_DUMP_ZAM", analysis_options.dump_ZAM);
    check_env_opt("ZEEK_DUMP_FINAL_ZAM", analysis_options.dump_final_ZAM);
    check_env_opt("ZEEK_PROFILE", analysis_options.profile_ZAM);

    // Compile-to-C++-related options.
    check_env_opt("ZEEK_GEN_CPP", analysis_options.gen_CPP);
    check_env_opt("ZEEK_GEN_STANDALONE_CPP", analysis_options.gen_standalone_CPP);
    check_env_opt("ZEEK_COMPILE_ALL", analysis_options.compile_all);
    check_env_opt("ZEEK_REPORT_CPP", analysis_options.report_CPP);
    check_env_opt("ZEEK_USE_CPP", analysis_options.use_CPP);
    check_env_opt("ZEEK_ALLOW_COND", analysis_options.allow_cond);

    if ( analysis_options.gen_standalone_CPP ) {
        if ( analysis_options.only_files.empty() )
            reporter->FatalError("-O gen-standalone-C++ requires use of --optimize-files");

        analysis_options.gen_CPP = true;
    }

    if ( analysis_options.gen_CPP )
        generating_CPP = true;

    if ( analysis_options.use_CPP && generating_CPP )
        reporter->FatalError("generating C++ incompatible with using C++");

    if ( analysis_options.allow_cond && ! generating_CPP )
        reporter->FatalError("\"-O allow-cond\" only relevant when using \"-O gen-C++\" or \"-O gen-standalone-C++\"");

    auto usage = getenv("ZEEK_USAGE_ISSUES");

    if ( usage )
        analysis_options.usage_issues = 1;

    if ( analysis_options.only_funcs.empty() ) {
        auto zo = getenv("ZEEK_OPT_FUNCS");
        if ( zo )
            add_func_analysis_pattern(analysis_options, zo, true);
    }

    if ( analysis_options.skip_funcs.empty() ) {
        auto zo = getenv("ZEEK_SKIP_FUNCS");
        if ( zo )
            add_func_analysis_pattern(analysis_options, zo, false);
    }

    if ( analysis_options.only_files.empty() ) {
        auto zo = getenv("ZEEK_OPT_FILES");
        if ( zo )
            add_file_analysis_pattern(analysis_options, zo, true);
    }

    if ( analysis_options.skip_files.empty() ) {
        auto zo = getenv("ZEEK_SKIP_FILES");
        if ( zo )
            add_file_analysis_pattern(analysis_options, zo, false);
    }

    if ( analysis_options.profile_ZAM ) {
        auto zsamp = getenv("ZEEK_ZAM_PROF_SAMPLING_RATE");
        if ( zsamp ) {
            analysis_options.profile_sampling_rate = atoi(zsamp);
            if ( analysis_options.profile_sampling_rate == 0 ) {
                fprintf(stderr, "bad ZAM sampling profile rate from $ZEEK_ZAM_PROF_SAMPLING_RATE: %s\n", zsamp);
                analysis_options.profile_ZAM = false;
            }
        }

        // If no ZAM generation options have been specified, default to
        // the usual "-O ZAM" profile. But if they have, honor those.
        if ( ! analysis_options.gen_ZAM_code )
            analysis_options.gen_ZAM = true;

        estimate_ZAM_profiling_overhead();
    }

    if ( analysis_options.gen_ZAM ) {
        analysis_options.gen_ZAM_code = true;
        analysis_options.inliner = true;
        analysis_options.optimize_AST = true;
    }

    if ( analysis_options.dump_ZAM )
        analysis_options.dump_final_ZAM = analysis_options.gen_ZAM_code = true;

    if ( ! analysis_options.only_funcs.empty() || ! analysis_options.only_files.empty() ) {
        if ( analysis_options.gen_ZAM_code || generating_CPP )
            analysis_options.report_uncompilable = true;
    }

    if ( analysis_options.report_uncompilable && ! analysis_options.gen_ZAM_code && ! generating_CPP )
        reporter->FatalError("report-uncompilable requires generation of ZAM or C++");

    if ( analysis_options.optimize_AST || analysis_options.gen_ZAM_code || analysis_options.usage_issues > 0 )
        analysis_options.activate = true;

    if ( analysis_options.no_inliner )
        analysis_options.inliner = false;
}

static void report_CPP() {
    if ( ! CPP_init_hook )
        reporter->FatalError("no C++ script bodies available");

    printf("C++ script bodies available that match loaded scripts:\n");

    std::unordered_set<unsigned long long> already_reported;

    for ( auto& f : funcs ) {
        const auto& name = f.Func()->GetName();

        if ( f.ShouldSkip() ) {
            printf("script function %s: SKIP\n", name.c_str());
            continue;
        }

        auto hash = f.Profile()->HashVal();
        bool have = compiled_scripts.contains(hash);

        printf("script function %s (hash %llu): %s\n", name.c_str(), hash, have ? "yes" : "no");

        if ( have )
            already_reported.insert(hash);
    }

    printf("\nAdditional C++ script bodies available:\n");

    int addl = 0;
    for ( const auto& s : compiled_scripts )
        if ( ! already_reported.contains(s.first) ) {
            printf("%s body (hash %llu)\n", s.second.body->Name().c_str(), s.first);
            ++addl;
        }

    if ( addl == 0 )
        printf("(none)\n");
}

static void use_CPP() {
    if ( ! CPP_init_hook )
        reporter->FatalError("no C++ functions available to use");

    int num_used = 0;

    auto pfs = std::make_unique<ProfileFuncs>(funcs, is_CPP_compilable, true, false);

    for ( auto& f : funcs ) {
        if ( f.ShouldSkip() )
            continue;

        auto hash = f.Profile()->HashVal();
        auto s = compiled_scripts.find(hash);

        if ( s != compiled_scripts.end() ) {
            ++num_used;

            auto b = s->second.body;

            // We may have already updated the body if
            // we're using code compiled for standalone.
            if ( f.Body()->Tag() != STMT_CPP ) {
                auto func = f.Func();
                if ( added_bodies[func->GetName()].contains(hash) )
                    // We've already added the
                    // replacement.  Delete orig.
                    func->ReplaceBody(f.Body(), nullptr);
                else
                    func->ReplaceBody(f.Body(), b);

                f.SetBody(b);
            }

            for ( auto& e : s->second.events )
                event_registry->Register(e);

            auto finish = s->second.finish_init_func;
            if ( finish )
                (*finish)();
        }
    }

    if ( num_used == 0 )
        reporter->FatalError("no C++ functions found to use");
}

static void generate_CPP(std::shared_ptr<ProfileFuncs> pfs) {
    const auto gen_name = CPP_dir + "CPP-gen.cc";

    const bool standalone = analysis_options.gen_standalone_CPP;
    const bool report = analysis_options.report_uncompilable;

    CPPCompile cpp(funcs, std::move(pfs), gen_name, standalone, report);
}

static void analyze_scripts_for_ZAM(std::shared_ptr<ProfileFuncs> pfs) {
    if ( analysis_options.usage_issues > 0 && analysis_options.optimize_AST ) {
        fprintf(stderr,
                "warning: \"-O optimize-AST\" option is incompatible with -u option, "
                "deactivating optimization\n");
        analysis_options.optimize_AST = false;
    }

    if ( analysis_options.profile_ZAM ) {
#ifdef ENABLE_ZAM_PROFILE
        AST_blocks = std::make_unique<ASTBlockAnalyzer>(funcs);
        const auto prof_filename = "zprof.out";
        analysis_options.profile_file = fopen(prof_filename, "w");
        if ( ! analysis_options.profile_file )
            reporter->FatalError("cannot create ZAM profiling log %s", prof_filename);
#else
        fprintf(stderr, "warning: zeek was not built with --enable-ZAM-profiling\n");
        analysis_options.profile_ZAM = false;
#endif
    }

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

    if ( inl ) {
        if ( global_stmts )
            func_used_indirectly.insert(global_stmts.get());

        for ( auto& g : pfs->Globals() ) {
            if ( g->GetType()->Tag() != TYPE_FUNC )
                continue;

            const auto& v = g->GetVal();
            if ( v )
                func_used_indirectly.insert(v->AsFunc());
        }
    }

    bool did_one = false;

    for ( auto& f : funcs ) {
        if ( ! f.ShouldAnalyze() )
            continue;

        auto& func = f.FuncPtr();
        auto l = lambdas.find(func.get());
        bool is_lambda = l != lambdas.end();

        if ( ! analysis_options.compile_all && ! is_lambda && inl && inl->WasFullyInlined(func.get()) &&
             ! func_used_indirectly.contains(func.get()) ) {
            // No need to compile as it won't be called directly.  We'd
            // like to zero out the body to recover the memory, but a *few*
            // such functions do get called, such as by the event engine
            // reaching up, or BiFs looking for them, so we can't safely
            // zero them.
            f.SetSkip(true);
            continue;
        }

        auto new_body = f.Body();
        optimize_func(func, f.ProfilePtr(), pfs, f.Scope(), new_body);
        f.SetBody(new_body);

        if ( is_lambda )
            l->second->ReplaceBody(new_body);

        did_one = true;
    }

    if ( ! did_one )
        reporter->FatalError("no matching functions/files for -O ZAM");

    finalize_functions(funcs);
}

void clear_script_analysis() {
    if ( analysis_options.gen_CPP )
        return;

    IDOptInfo::ClearGlobalInitExprs();

    // We need to explicitly clear out the optimization information
    // associated with identifiers.  They have reference loops with
    // the parent identifier that will prevent reclamation of the
    // identifiers (and the optimization information) upon Unref'ing
    // when discarding the scopes and ASTs.
    for ( auto& f : funcs )
        for ( auto& id : f.Scope()->OrderedVars() )
            id->ClearOptInfo();

    // Clear out optimization info for global variables, too.
    for ( auto& g : global_scope()->OrderedVars() )
        g->ClearOptInfo();

    // Keep the functions around if we're profiling, so we can loop
    // over them to generate the profiles.
    if ( ! analysis_options.profile_ZAM )
        funcs.clear();

    non_recursive_funcs.clear();
    lambdas.clear();
    when_lambdas.clear();
}

void analyze_scripts(bool no_unused_warnings) {
    init_options();

    if ( analysis_options.validate_ZAM ) {
        validate_ZAM_insts();
        return;
    }

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
         ! analysis_options.report_CPP && ! analysis_options.use_CPP ) { // No work to do, avoid profiling overhead.
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
            func.SetShouldNotAnalyze();

    if ( ! have_one_to_do )
        reporter->FatalError("no matching functions/files for script optimization");

    if ( CPP_init_hook ) {
        (*CPP_init_hook)();
        if ( compiled_scripts.empty() )
            // The initialization failed to produce any
            // script bodies.  Make this easily available
            // to subsequent checks.
            CPP_init_hook = nullptr;
    }

    if ( analysis_options.report_CPP ) {
        auto pfs = std::make_unique<ProfileFuncs>(funcs, is_CPP_compilable, true, false);
        report_CPP();
        exit(0);
    }

    if ( analysis_options.use_CPP )
        use_CPP();

    if ( generating_CPP ) {
        if ( analysis_options.gen_ZAM )
            reporter->FatalError("-O ZAM and -O gen-C++ conflict");

        auto pfs = std::make_shared<ProfileFuncs>(funcs, is_CPP_compilable, true, false);
        generate_CPP(std::move(pfs));
        exit(0);
    }

    auto pfs = std::make_shared<ProfileFuncs>(funcs, nullptr, true, true);
    analyze_scripts_for_ZAM(std::move(pfs));

    if ( reporter->Errors() > 0 )
        reporter->FatalError("Optimized script execution aborted due to errors");
}

void profile_script_execution() {
    if ( analysis_options.profile_ZAM ) {
        report_ZOP_profile();

        ProfMap module_prof;

        for ( auto& f : funcs ) {
            if ( f.Body()->Tag() == STMT_ZAM ) {
                auto zb = cast_intrusive<ZBody>(f.Body());
                zb->ReportExecutionProfile(module_prof);
            }
        }

        for ( auto& mp : module_prof )
            if ( mp.second.num_samples > 0 )
                fprintf(analysis_options.profile_file, "module %s sampled CPU time %.06f, %d sampled instructions\n",
                        mp.first.c_str(), mp.second.CPU_time, static_cast<int>(mp.second.num_samples));
    }
}

void finish_script_execution() { profile_script_execution(); }

// For now, we have equivalent concerns between ZAM and compile-to-C++.
bool has_AST_node_unknown_to_script_opt(const ProfileFunc* prof, bool /* is_ZAM */) {
    // Note that the following sets are not comprehensive across the
    // standard tags, because some tags are only generated *by* script
    // optimization
    // clang-format off
    static const std::set<StmtTag> known_stmts = {
        // STMT_ALARM
        STMT_PRINT,
        STMT_EVENT,
        STMT_EXPR,
        STMT_IF,
        STMT_WHEN,
        STMT_SWITCH,
        STMT_FOR,
        STMT_NEXT,
        STMT_BREAK,
        STMT_RETURN,
        STMT_LIST,
        // STMT_EVENT_BODY_LIST,
        STMT_INIT,
        STMT_FALLTHROUGH,
        STMT_WHILE,
        // STMT_CATCH_RETURN,
        // STMT_CHECK_ANY_LEN,
        // STMT_CPP,
        // STMT_ZAM,
        STMT_NULL,
        STMT_ASSERT,
        // STMT_EXTERN,
        // STMT_STD_FUNCTION,
    };

    // This should be the total number of entries in the set above, including
    // the commented values.
    constexpr int SCRIPT_OPT_NUM_STMTS = 24;

    // clang-format on

    // Fail compilation if NUM_STMT in StmtEnums.h changes.
    // Update known_stmts list above appropriately after adding
    // support and increase SCRIPT_OPT_NUM_STMTS.
    static_assert(NUM_STMTS == SCRIPT_OPT_NUM_STMTS);

    for ( auto& s : prof->Stmts() )
        if ( ! known_stmts.contains(s->Tag()) )
            return true;

    // clang-format off
    static const std::set<ExprTag> known_exprs = {
        // EXPR_ANY,
        EXPR_NAME,
        EXPR_CONST,
        EXPR_CLONE,
        EXPR_INCR,
        EXPR_DECR,
        EXPR_NOT,
        EXPR_COMPLEMENT,
        EXPR_POSITIVE,
        EXPR_NEGATE,
        EXPR_ADD, EXPR_SUB,
        EXPR_AGGR_ADD,
        EXPR_AGGR_DEL,
        EXPR_ADD_TO,
        EXPR_REMOVE_FROM,
        EXPR_TIMES,
        EXPR_DIVIDE,
        EXPR_MASK,
        EXPR_MOD,
        EXPR_AND,
        EXPR_OR,
        EXPR_XOR,
        EXPR_LSHIFT,
        EXPR_RSHIFT,
        EXPR_AND_AND,
        EXPR_OR_OR,
        EXPR_LT,
        EXPR_LE,
        EXPR_EQ,
        EXPR_NE,
        EXPR_GE,
        EXPR_GT,
        EXPR_COND,
        EXPR_REF,
        EXPR_ASSIGN,
        EXPR_INDEX,
        EXPR_FIELD,
        EXPR_HAS_FIELD,
        EXPR_RECORD_CONSTRUCTOR,
        EXPR_TABLE_CONSTRUCTOR,
        EXPR_SET_CONSTRUCTOR,
        EXPR_VECTOR_CONSTRUCTOR,
        EXPR_FIELD_ASSIGN,
        EXPR_IN,
        EXPR_LIST,
        EXPR_CALL,
        EXPR_LAMBDA,
        EXPR_EVENT,
        EXPR_SCHEDULE,
        EXPR_ARITH_COERCE,
        EXPR_RECORD_COERCE,
        EXPR_TABLE_COERCE,
        EXPR_VECTOR_COERCE,
        EXPR_TO_ANY_COERCE,
        EXPR_FROM_ANY_COERCE,
        EXPR_SIZE,
        EXPR_CAST,
        EXPR_IS,
        // EXPR_INDEX_SLICE_ASSIGN,
        EXPR_INLINE,
        // EXPR_APPEND_TO,
        // EXPR_INDEX_ASSIGN,
        // EXPR_FIELD_LHS_ASSIGN,
        // EXPR_REC_ASSIGN_FIELDS,
        // EXPR_REC_ADD_FIELDS,
        // EXPR_REC_CONSTRUCT_WITH_REC,
        // EXPR_FROM_ANY_VEC_COERCE,
        // EXPR_ANY_INDEX,
        // EXPR_SCRIPT_OPT_BUILTIN,
        // EXPR_NOP,
    };

    // This should be the total number of entries in the set above, including
    // the commented values.
    constexpr int SCRIPT_OPT_NUM_EXPRS = 70;

    // clang-format on

    // Fail compilation if NUM_EXPRS in Expr.h changes.
    // Update known_exprs list above appropriately after
    // adding support and increase SCRIPT_OPT_NUM_STMTS.
    static_assert(NUM_EXPRS == SCRIPT_OPT_NUM_EXPRS);

    for ( auto& e : prof->Exprs() )
        if ( ! known_exprs.contains(e->Tag()) )
            return true;

    return false;
}

} // namespace zeek::detail
