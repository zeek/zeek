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

namespace zeek::detail {

AnalyOpt analysis_options;

std::unordered_set<const Func*> non_recursive_funcs;

void (*CPP_init_hook)() = nullptr;
void (*CPP_activation_hook)() = nullptr;

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

bool is_lambda(const ScriptFunc* f) { return lambdas.count(f) > 0; }

bool is_when_lambda(const ScriptFunc* f) { return when_lambdas.count(f) > 0; }

void analyze_global_stmts(Stmt* stmts) {
    // We ignore analysis_options.only_{files,funcs} - if they're in use, later
    // logic will keep this function from being compiled, but it's handy
    // now to enter it into "funcs" so we have a FuncInfo to return.

    auto id = install_ID("<global-stmts>", GLOBAL_MODULE_NAME, true, false);
    auto empty_args_t = make_intrusive<RecordType>(nullptr);
    auto func_t = make_intrusive<FuncType>(empty_args_t, nullptr, FUNC_FLAVOR_FUNCTION);
    id->SetType(func_t);

    auto sc = current_scope();
    std::vector<IDPtr> empty_inits;
    global_stmts = make_intrusive<ScriptFunc>(id);
    global_stmts->AddBody(stmts->ThisPtr(), empty_inits, sc->Length());

    global_stmts_ind = funcs.size();
    funcs.emplace_back(global_stmts, sc, stmts->ThisPtr(), 0);
}

std::pair<StmtPtr, ScopePtr> get_global_stmts() {
    ASSERT(global_stmts);
    auto& fi = funcs[global_stmts_ind];
    return std::pair<StmtPtr, ScopePtr>{fi.Body(), fi.Scope()};
}

void add_func_analysis_pattern(AnalyOpt& opts, const char* pat) {
    try {
        std::string full_pat = std::string("^(") + pat + ")$";
        opts.only_funcs.emplace_back(full_pat);
    } catch ( const std::regex_error& e ) {
        reporter->FatalError("bad file analysis pattern: %s", pat);
    }
}

void add_file_analysis_pattern(AnalyOpt& opts, const char* pat) {
    try {
        std::string full_pat = std::string("^.*(") + pat + ").*$";
        opts.only_files.emplace_back(full_pat);
    } catch ( const std::regex_error& e ) {
        reporter->FatalError("bad file analysis pattern: %s", pat);
    }
}

bool should_analyze(const ScriptFuncPtr& f, const StmtPtr& body) {
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
            printf("Skipping compilation of %s due to %s\n", f->Name(), reason);
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

        if ( analysis_options.dump_ZAM )
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
        reporter->FatalError("\"-O allow-cond\" only relevant when also using \"-O gen-standalone-C++\"");

    auto usage = getenv("ZEEK_USAGE_ISSUES");

    if ( usage )
        analysis_options.usage_issues = 1;

    if ( analysis_options.only_funcs.empty() ) {
        auto zo = getenv("ZEEK_OPT_FUNCS");
        if ( zo )
            add_func_analysis_pattern(analysis_options, zo);
    }

    if ( analysis_options.only_files.empty() ) {
        auto zo = getenv("ZEEK_OPT_FILES");
        if ( zo )
            add_file_analysis_pattern(analysis_options, zo);
    }

    if ( analysis_options.gen_ZAM ) {
        analysis_options.gen_ZAM_code = true;
        analysis_options.inliner = true;
        analysis_options.optimize_AST = true;
    }

    if ( analysis_options.dump_ZAM )
        analysis_options.gen_ZAM_code = true;

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
        if ( already_reported.count(s.first) == 0 ) {
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

    auto pfs = std::make_unique<ProfileFuncs>(funcs, is_CPP_compilable, false);

    for ( auto& f : funcs ) {
        auto hash = f.Profile()->HashVal();
        auto s = compiled_scripts.find(hash);

        if ( s != compiled_scripts.end() ) {
            ++num_used;

            auto b = s->second.body;
            b->SetHash(hash);

            // We may have already updated the body if
            // we're using code compiled for standalone.
            if ( f.Body()->Tag() != STMT_CPP ) {
                auto func = f.Func();
                if ( added_bodies[func->Name()].count(hash) > 0 )
                    // We've already added the
                    // replacement.  Delete orig.
                    func->ReplaceBody(f.Body(), nullptr);
                else
                    func->ReplaceBody(f.Body(), b);

                f.SetBody(b);
            }

            for ( auto& e : s->second.events ) {
                auto h = event_registry->Register(e);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
                h->SetUsed();
#pragma GCC diagnostic pop
            }

            auto finish = s->second.finish_init_func;
            if ( finish )
                (*finish)();
        }
    }

    if ( num_used == 0 )
        reporter->FatalError("no C++ functions found to use");
}

static void generate_CPP() {
    const auto gen_name = CPP_dir + "CPP-gen.cc";

    const bool standalone = analysis_options.gen_standalone_CPP;
    const bool report = analysis_options.report_uncompilable;

    auto pfs = std::make_shared<ProfileFuncs>(funcs, is_CPP_compilable, false);

    CPPCompile cpp(funcs, pfs, gen_name, standalone, report);
}

static void analyze_scripts_for_ZAM() {
    if ( analysis_options.usage_issues > 0 && analysis_options.optimize_AST ) {
        fprintf(stderr,
                "warning: \"-O optimize-AST\" option is incompatible with -u option, "
                "deactivating optimization\n");
        analysis_options.optimize_AST = false;
    }

    auto pfs = std::make_shared<ProfileFuncs>(funcs, nullptr, true);

    if ( analysis_options.profile_ZAM )
        basic_blocks = std::make_unique<BBAnalyzer>(funcs);

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

            auto v = g->GetVal();
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
             func_used_indirectly.count(func.get()) == 0 ) {
            // No need to compile as it won't be called directly.
            // We'd like to zero out the body to recover the
            // memory, but a *few* such functions do get called,
            // such as by the event engine reaching up, or
            // BiFs looking for them, so we can't safely zero
            // them.
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
    IDOptInfo::ClearGlobalInitExprs();

    // Keep the functions around if we're debugging, so we can
    // generate profiles.
#ifndef DEBUG
    // We need to explicitly clear out the optimization information
    // associated with identifiers.  They have reference loops with
    // the parent identifier that will prevent reclamation of the
    // identifiers (and the optimization information) upon Unref'ing
    // when discarding the scopes and ASTs.
    for ( auto& f : funcs )
        for ( auto& id : f.Scope()->OrderedVars() )
            id->ClearOptInfo();

    funcs.clear();
#endif

    non_recursive_funcs.clear();
    lambdas.clear();
    when_lambdas.clear();
}

void analyze_scripts(bool no_unused_warnings) {
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
        reporter->FatalError("no matching functions/files for C++ compilation");

    if ( CPP_init_hook ) {
        (*CPP_init_hook)();
        if ( compiled_scripts.empty() )
            // The initialization failed to produce any
            // script bodies.  Make this easily available
            // to subsequent checks.
            CPP_init_hook = nullptr;
    }

    if ( analysis_options.report_CPP ) {
        report_CPP();
        exit(0);
    }

    if ( analysis_options.use_CPP )
        use_CPP();

    if ( generating_CPP ) {
        if ( analysis_options.gen_ZAM )
            reporter->FatalError("-O ZAM and -O gen-C++ conflict");

        generate_CPP();
        exit(0);
    }

    // At this point we're done with C++ considerations, so instead
    // are compiling to ZAM.
    analyze_scripts_for_ZAM();

    if ( reporter->Errors() > 0 )
        reporter->FatalError("Optimized script execution aborted due to errors");
}

class ProfileBlock {
public:
    ProfileBlock(const ProfileElem* pe) {
        auto& loc = pe->Loc();
        min_first_line = max_first_line = loc->first_line;
        min_last_line = max_last_line = loc->last_line;
        prof_elems.push_back(pe);
    }

    void AddProfileElem(const ProfileElem* pe) {
        auto& loc = pe->Loc();
        min_first_line = std::min(min_first_line, loc->first_line);
        max_first_line = std::max(max_first_line, loc->first_line);
        min_last_line = std::min(min_last_line, loc->last_line);
        max_last_line = std::max(max_last_line, loc->last_line);
        prof_elems.push_back(pe);
    }

    bool BasicBlockFits(const Location* loc);

    const auto& ProfElems() const { return prof_elems; }

private:
    std::vector<const ProfileElem*> prof_elems;
    int min_first_line, max_first_line;
    int min_last_line, max_last_line;
};

bool ProfileBlock::BasicBlockFits(const Location* loc) {
    for ( auto& p : prof_elems ) {
        auto& pl = p->Loc();
        if ( loc->first_line <= pl->first_line && loc->last_line >= pl->last_line )
            return true;
    }

    return false;
}

class FileProfInfo {
public:
    FileProfInfo(std::string _filename, const ProfileElem* pe) : filename(std::move(_filename)) { AddProfileElem(pe); }

    void AddProfileElem(const ProfileElem* pe) {
        base_profs.push_back(pe);
        max_line = std::max(max_line, pe->Loc()->last_line);
    }

    void AddBasicBlock(const Location* bb);

    void CompileProfileElems();
    void CompileBasicBlocks();

    void Report();

private:
    std::shared_ptr<ProfileElem> UpdateBBProfile(const Location* bb);

    std::string filename;

    std::vector<const ProfileElem*> base_profs;
    std::unordered_set<const Location*> bbs;

    std::vector<std::shared_ptr<ProfileBlock>> profile_blocks;
    std::vector<std::shared_ptr<ProfileElem>> full_profs;

    int max_line = 0;
};

void FileProfInfo::CompileProfileElems() {
    profile_blocks.resize(max_line + 1);
    full_profs.resize(max_line + 1);

    for ( auto p : base_profs ) {
        auto loc = p->Loc();
        for ( int i = loc->first_line; i <= loc->last_line; ++i ) {
            if ( ! profile_blocks[i] )
                profile_blocks[i] = std::make_shared<ProfileBlock>(p);
            else
                profile_blocks[i]->AddProfileElem(p);
        }
    }
}

void FileProfInfo::AddBasicBlock(const Location* bb) {
    if ( bb->last_line > max_line )
        return;

    for ( auto i = bb->first_line; i <= bb->last_line; ++i ) {
        auto& pb = profile_blocks[i];
        if ( pb && pb->BasicBlockFits(bb) ) {
            bbs.insert(bb);
            break;
        }
    }
}

void FileProfInfo::CompileBasicBlocks() {
    // Ordered by size of the block.
    std::vector<const Location*> ordered_bbs;

    for ( auto bb : bbs )
        ordered_bbs.push_back(bb);

    std::sort(ordered_bbs.begin(), ordered_bbs.end(), [](const Location* l1, const Location* l2) {
        return l1->last_line - l1->first_line < l2->last_line - l2->first_line;
    });

    for ( auto bb : ordered_bbs ) {
        auto prof = UpdateBBProfile(bb);
        if ( ! prof )
            continue;

        auto& loc = prof->Loc();
        printf("%s:%d", filename.c_str(), loc->first_line);
        if ( loc->first_line < loc->last_line )
            printf("-%d", loc->last_line);

        printf(" %" PRId64 " %.06f\n", prof->Count(), prof->CPU());
    }
}

std::shared_ptr<ProfileElem> FileProfInfo::UpdateBBProfile(const Location* bb) {
    auto& fp1 = full_profs[bb->first_line];

    if ( fp1 ) {
        ASSERT(fp1->Loc()->last_line <= bb->last_line);
        if ( *fp1->Loc() == *bb )
            // Already have it.
            return nullptr;
    }

    // Need to create a new profile.
    auto bb_loc = std::make_shared<Location>(*bb);
    auto new_fp = std::make_shared<ProfileElem>(bb_loc);

    int num_pb_merged = 0;
    int num_fp_merged = 0;

    for ( int i = bb->first_line; i <= bb->last_line; ++i ) {
        const auto& fpi = full_profs[i];
        if ( fpi ) {
            ++num_fp_merged;
            new_fp->MergeIn(fpi.get());
            // Skip past what's already accounted for in this
            // aggregation.
            i = new_fp->Loc()->last_line;
            continue;
        }

        auto& pb_i = profile_blocks[i];
        if ( ! pb_i )
            continue;

        for ( auto pe : pb_i->ProfElems() )
            if ( pe->Loc()->first_line == i ) {
                ++num_pb_merged;
                new_fp->MergeIn(pe);
            }

#if 0
		// Avoid double-counting in the future.
		pb_i = nullptr;
#endif
    }

    ASSERT(new_fp->Count() > 0);

    fp1 = std::move(new_fp);

    if ( num_fp_merged == 1 && num_pb_merged == 0 )
        // This is not a consolidation but just an expansion of range.
        return nullptr;

    return fp1;
}

void FileProfInfo::Report() {
#if 0
	for ( auto p : base_profs )
		{
		auto pb = std::make_shared<ProfileBlock>(p);
		auto loc = p->Loc();
		for ( int i = loc->first_line; i <= loc->last_line; ++i )
			profile_blocks[i]->AddProfileElem(pb);
		}
#endif
}

void profile_script_execution() {
    if ( ! analysis_options.profile_ZAM )
        return;

    report_ZOP_profile();

    // Collect all of the profiles (and do initial reporting on them).
    std::unordered_map<std::string, std::shared_ptr<FileProfInfo>> file_profs;

    for ( auto& f : funcs ) {
        if ( f.Body()->Tag() != STMT_ZAM )
            continue;

        auto zb = cast_intrusive<ZBody>(f.Body());
        zb->ProfileExecution();

        for ( auto& pe : zb->ExecProfile() ) {
            if ( pe.Count() == 0 )
                continue;

            auto loc = pe.Loc();
            auto fp = file_profs.find(loc->filename);
            if ( fp == file_profs.end() )
                file_profs[loc->filename] = std::make_shared<FileProfInfo>(loc->filename, &pe);
            else
                fp->second->AddProfileElem(&pe);
        }
    }

    for ( auto& fp : file_profs )
        fp.second->CompileProfileElems();

    for ( auto& bb : basic_blocks->BasicBlocks() ) {
        auto& loc = bb.second;
        auto fp = file_profs.find(loc.filename);
        if ( fp != file_profs.end() )
            fp->second->AddBasicBlock(&loc);
    }

    for ( auto& fp : file_profs )
        fp.second->CompileBasicBlocks();

    for ( auto& fp : file_profs )
        fp.second->Report();

#if 0
    // Put together a mapping of filenames to associated locations. In the
    // process, compute per-file its largest line number.
    auto& bb = basic_blocks->BasicBlocks();
    std::unordered_map<std::string, std::unordered_set<const Location*>> file_bbs_seen;
    std::unordered_map<std::string, int> file_size;

    for ( auto& b : bb ) {
        auto& bl = b.second;
        auto bmax = bl.last_line;
        auto bf = bl.filename;
        auto fs_b = file_size.find(bf);
        if ( fs_b == file_size.end() )
            file_size[bf] = bmax;
        else
            fs_b->second = std::max(fs_b->second, bmax);

        auto fb = file_bbs_seen.find(bf);
        if ( fb == file_bbs_seen.end() )
            file_bbs_seen[bf] = std::unordered_set<const Location*>{&bl};
        else
            fb->second.insert(&bl);
    }

    std::unordered_map<std::string, std::vector<std::pair<zeek_uint_t, double>>> loc_info;

    for ( auto& fs : file_size ) {
        auto stats = std::vector<std::pair<zeek_uint_t, double>>{};
        stats.resize(fs.second + 1);
        loc_info[fs.first] = std::move(stats);
    }

    for ( auto& f : funcs ) {
        if ( f.Body()->Tag() == STMT_ZAM ) {
            auto zb = cast_intrusive<ZBody>(f.Body());
            zb->ProfileExecution();

            for ( auto& pe : zb->ExecProfile() ) {
                if ( pe.Count() == 0 )
                    continue;

                auto& loc = pe.Loc();
                auto li = loc_info.find(loc->filename);
                ASSERT(li != loc_info.end());

                auto first = loc->first_line;
                auto last = loc->last_line;
                if ( last < first )
                    std::swap(first, last);

                li->second[first].first += pe.Count();
                li->second[first].second += pe.CPU();

			for ( auto i = first; i <= last; ++i )
				{
				li->second[i].first += pe.Count();
				li->second[i].second += pe.CPU();
				}
            }
        }
    }

    std::unordered_set<std::string> locs_reported;

    for ( auto& b : file_bbs ) {
        auto& loc = b.first;

        for ( auto& bb : b.second ) {
            auto& fn = bb->filename;
            if ( loc_info.count(fn) == 0 ) {
                printf("NO LOC INFO: %s\n", fn);
                continue;
            }

            auto lstr = std::string(fn) + ":" + std::to_string(bb->first_line);
            if ( bb->last_line != bb->first_line )
                lstr += "-" + std::to_string(bb->last_line);

            if ( locs_reported.count(lstr) > 0 )
                continue;

            locs_reported.insert(lstr);

            zeek_uint_t count = 0;
            double CPU = 0.0;

            auto& li = loc_info[fn];
            for ( auto i = bb->first_line; i <= bb->last_line; ++i ) {
                auto& li_i = li[i];
                count += li_i.first;
                CPU += li_i.second;
            }

            printf("%s %d %" PRId64 " %.06f\n", lstr.c_str(), 1 + bb->last_line - bb->first_line, count, CPU);
        }
    }
#endif
}

void finish_script_execution() { profile_script_execution(); }

} // namespace zeek::detail
