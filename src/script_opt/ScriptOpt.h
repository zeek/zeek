// See the file "COPYING" in the main distribution directory for copyright.

// Classes for controlling/orchestrating script optimization & compilation.

#pragma once

#include <regex>
#include <string>
#include <unordered_set>
#include <vector>

#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/Scope.h"

namespace zeek {
struct Options;
}

namespace zeek::detail {

using ObjPtr = IntrusivePtr<Obj>;
using TypeSet = std::unordered_set<const Type*>;

// Flags controlling what sorts of analysis to do.

struct AnalyOpt {
    // If non-nil, then only analyze function/event/hook(s) whose names
    // match one of the given regular expressions.
    //
    // Applies to both ZAM and C++.
    std::vector<std::regex> only_funcs;

    // Same, but for the filenames where the function is found.
    std::vector<std::regex> only_files;

    // The inverses of those - functions and files to skip. These
    // have higher precedence than the only_'s.
    std::vector<std::regex> skip_funcs;
    std::vector<std::regex> skip_files;

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

    // If true, suppress global inlining.  A separate option because
    // it needs to override situations where "inliner" is implicitly
    // enabled due to other options.
    bool no_inliner = false;

    // If true, when inlining skip event handler coalescence.
    bool no_eh_coalescence = false;

    // Whether to keep or elide "assert" statements.
    bool keep_asserts = false;

    // If true, report which functions are directly and indirectly
    // recursive, and exit.  Only germane if running the inliner.
    bool report_recursive = false;

    // If true, assess the instructions generated from ZAM templates
    // for validity, and exit.
    bool validate_ZAM = false;

    // If true, generate ZAM code for applicable function bodies,
    // activating all optimizations.
    bool gen_ZAM = false;

    // Generate ZAM code, but do not turn on optimizations unless
    // specified.
    bool gen_ZAM_code = false;

    // Deactivate the low-level ZAM optimizer.
    bool no_ZAM_opt = false;

    // Deactivate ZAM optimization of control flow.
    bool no_ZAM_control_flow_opt = false;

    // Produce a profile of ZAM execution.
    bool profile_ZAM = false;

    // ZAM profiling sampling rate. Set via ZEEK_ZAM_PROF_SAMPLING_RATE.
    int profile_sampling_rate = 100;

    // An associated file to which to write the profile.
    FILE* profile_file = nullptr;

    // If true, dump out transformed code: the results of reducing
    // interpreted scripts, and, if optimize is set, of then optimizing
    // them.
    bool dump_xform = false;

    // If true, dump out the use-defs for each analyzed function.
    bool dump_uds = false;

    // If true, dump out generated ZAM code, including intermediaries.
    bool dump_ZAM = false;

    // If true, dump out final generated ZAM code (only).
    bool dump_final_ZAM = false;

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

class ProfileFunc;

using ScriptFuncPtr = IntrusivePtr<ScriptFunc>;

// Info we need for tracking an instance of a function.
class FuncInfo {
public:
    FuncInfo(ScriptFuncPtr _func, ScopePtr _scope, Func::Body _body)
        : func(std::move(_func)), scope(std::move(_scope)), body(std::move(_body)) {}

    ScriptFunc* Func() const { return func.get(); }
    const ScriptFuncPtr& FuncPtr() const { return func; }
    const ScopePtr& Scope() const { return scope; }
    const StmtPtr& Body() const { return body.stmts; }
    int Priority() const { return body.priority; }
    auto EventGroups() const { return body.groups; }
    const ProfileFunc* Profile() const { return pf.get(); }
    std::shared_ptr<ProfileFunc> ProfilePtr() const { return pf; }

    void SetScope(ScopePtr new_scope) { scope = std::move(new_scope); }
    void SetBody(StmtPtr new_body) { body.stmts = std::move(new_body); }
    void SetProfile(std::shared_ptr<ProfileFunc> _pf) { pf = std::move(_pf); }

    bool ShouldAnalyze() const { return should_analyze; }
    void SetShouldNotAnalyze() {
        should_analyze = false;
        skip = true;
    }

    // The following provide a way of marking FuncInfo's as
    // should-be-skipped for a given phase of script optimization.
    bool ShouldSkip() const { return skip; }
    void SetSkip(bool should_skip) { skip = should_skip; }

protected:
    ScriptFuncPtr func;
    ScopePtr scope;
    Func::Body body;
    std::shared_ptr<ProfileFunc> pf;

    // Whether to analyze this function at all, per optimization selection
    // via --optimize-file/--optimize-func.  If those flags aren't used,
    // then this will remain true, given that both ZAM and -O gen-C++ are
    // feature-complete.
    bool should_analyze = true;

    // Whether to skip optimizing this function in a given context. May be
    // altered during optimization.
    bool skip = false;
};

// ScriptFunc subclass that runs a single (coalesced) body if possible,
// otherwise delegates to the original function with multiple bodies.
class CoalescedScriptFunc : public ScriptFunc {
public:
    CoalescedScriptFunc(Func::Body merged_body, ScopePtr scope, ScriptFuncPtr orig_func)
        : ScriptFunc(orig_func->GetName(), orig_func->GetType(), {std::move(merged_body)}), orig_func(orig_func) {
        SetScope(std::move(scope));
    };

    ValPtr Invoke(zeek::Args* args, Frame* parent) const override {
        // If the original function has all bodies enabled, run our
        // coalesced one, otherwise delegate.
        if ( orig_func->HasAllBodiesEnabled() )
            return ScriptFunc::Invoke(args, parent);

        return orig_func->Invoke(args, parent);
    }

private:
    ScriptFuncPtr orig_func;
};

// We track which functions are definitely not recursive.  We do this
// as the negative, rather than tracking functions known to be recursive,
// so that if we don't do the analysis at all (it's driven by inlining),
// we err on the conservative side and assume every function is recursive.
extern std::unordered_set<const Func*> non_recursive_funcs;

// Analyze a given function for optimization.
extern void analyze_func(ScriptFuncPtr f);

// Same, for lambdas.
extern void analyze_lambda(LambdaExpr* f);

// Same, for lambdas used in "when" statements.  For these, analyze_lambda()
// has already been called.
extern void analyze_when_lambda(LambdaExpr* f);

// Inform script optimization that we've instantiated a lambda (during
// initialization) and thus its AST has an alias.
extern void register_lambda_alias(const StmtPtr& orig, const StmtPtr& alias);

// Look up the original body associated with a given potential lambda alias.
// Returns nil if there's no such alias.
extern const Stmt* look_up_lambda_alias(const Stmt* alias);

// Whether a given script function is a lambda or (separately) a "when" lambda.
extern bool is_lambda(const ScriptFunc* f);
extern bool is_when_lambda(const ScriptFunc* f);

// Analyze the given top-level statement(s) for optimization.
extern void analyze_global_stmts(Stmt* stmts);

// Returns the body and scope for the previously analyzed global statements.
extern std::pair<StmtPtr, ScopePtr> get_global_stmts();

// Informs script optimization that parsing is switching to the given module.
// Used to associate module names with profiling information.
extern void switch_to_module(const char* module);

// Add a pattern to the "only_funcs" (if is_only true) or "skip_funcs" list.
extern void add_func_analysis_pattern(AnalyOpt& opts, const char* pat, bool is_only);

// Add a pattern to the "only_files" / "skip_files" list.
extern void add_file_analysis_pattern(AnalyOpt& opts, const char* pat, bool is_only);

// True if the given script function & body should be analyzed; otherwise
// it should be skipped.
extern bool should_analyze(const ScriptFuncPtr& f, const StmtPtr& body);

// SHOULD if the given filename or object location matches one specified by
// --optimize-files=..., SHOULD_NOT if it matches one specified by
// --no-opt-files=... (which takes precedence), DEFAULT if neither.
enum class AnalyzeDecision : uint8_t { SHOULD, SHOULD_NOT, DEFAULT };
extern AnalyzeDecision filename_matches_opt_files(const char* filename);
extern AnalyzeDecision obj_matches_opt_files(const Obj* obj);
inline auto obj_matches_opt_files(const ObjPtr& obj) { return obj_matches_opt_files(obj.get()); }

// Analyze all of the parsed scripts collectively for usage issues (unless
// suppressed by the flag) and optimization.
extern void analyze_scripts(bool no_unused_warnings);

// Conduct internal validation of ZAM instructions. Upon success, generates
// a terse report to stdout.  Exits with an internal error if a problem is
// encountered.
extern void validate_ZAM_insts();

// Called when all script processing is complete and we can discard
// unused ASTs and associated state.
extern void clear_script_analysis();

// Called when Zeek is terminating.
extern void finish_script_execution();

// Returns true if the given profile indicates the presence of an AST
// node not known to script optimization. The second argument specifies
// whether we're doing ZAM optimization; if not, compile-to-C++ is assumed.
extern bool has_AST_node_unknown_to_script_opt(const ProfileFunc* prof, bool /* is_ZAM */);

// Returns true if the given call has a specialized ZAM equivalent when
// used in a conditional.
extern bool IsZAM_BuiltInCond(const CallExpr* c);

// Used for C++-compiled scripts to signal their presence, by setting this
// to a non-empty value.
extern void (*CPP_init_hook)();

} // namespace zeek::detail
