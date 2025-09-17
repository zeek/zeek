// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/Inline.h"

#include "zeek/EventRegistry.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/Expr.h"
#include "zeek/script_opt/FuncInfo.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/StmtOptInfo.h"
#include "zeek/script_opt/ZAM/Support.h"

namespace zeek::detail {

constexpr int MAX_INLINE_SIZE = 1000;

void Inliner::Analyze() {
    // Locate self- and indirectly recursive functions.

    // Maps each function to any functions that it calls, either
    // directly or (ultimately) indirectly.
    std::unordered_map<const Func*, std::unordered_set<const Func*>> call_set;

    // Prime the call set for each function with the functions it
    // directly calls.
    for ( auto& f : funcs ) {
        // For any function explicitly known to the event engine, it can
        // be hard to analyze whether there's a possibility that when
        // executing the function, doing so will tickle the event engine
        // into calling it recursively. So we remove these up front.
        //
        // We deal with cases where these defaults are overridden to refer
        // to some other function below, when we go through indirect functions.
        if ( is_special_script_func(f.Func()->GetName()) )
            continue;

        // If ZAM can replace the script, don't inline it, so its usage
        // remains visible during the AST reduction process.
        if ( is_ZAM_replaceable_script_func(f.Func()->GetName()) )
            continue;

        std::unordered_set<const Func*> cs;

        // Aspirational ....
        non_recursive_funcs.insert(f.Func());

        for ( auto& func : f.Profile()->ScriptCalls() ) {
            cs.insert(func);

            if ( func == f.Func() ) {
                if ( report_recursive )
                    printf("%s is directly recursive\n", func->GetName().c_str());

                non_recursive_funcs.erase(func);
            }
        }

        call_set[f.Func()] = cs;

        for ( auto& ind_func : f.Profile()->IndirectFuncs() ) {
            auto& v = ind_func->GetVal();
            if ( ! v )
                // Global doesn't correspond to an actual function body.
                continue;

            auto vf = v->AsFunc();
            if ( vf->GetKind() != BuiltinFunc::SCRIPT_FUNC )
                // Not of analysis interest.
                continue;

            auto sf = static_cast<const ScriptFunc*>(vf);

            // If we knew transitively that the function lead to any
            // indirect calls, nor calls to unsafe BiFs that themselves
            // might do so, then we could know that this function isn't
            // recursive via indirection. It's not clear, however, that
            // identifying such cases is worth the trouble, other than
            // for cutting down noise from the following recursion report.

            if ( report_recursive )
                printf("%s is used indirectly, and thus potentially recursively\n", sf->GetName().c_str());

            non_recursive_funcs.erase(sf);
        }
    }

    // Transitive closure.  If we had any self-respect, we'd implement
    // Warshall's algorithm.  What we do here is feasible though since
    // Zeek call graphs tend not to be super-deep.  (We could also save
    // cycles by only analyzing non-[direct-or-indirect] leaves, as
    // was computed by the previous version of this code.  But in
    // practice, the execution time for this is completely dwarfed
    // by the expense of compiling inlined functions, so we keep it
    // simple.)

    // Whether a change has occurred.
    bool did_addition = true;
    while ( did_addition ) {
        did_addition = false;

        // Loop over all the functions of interest.
        for ( auto& c : call_set ) {
            // For each of them, loop over the set of functions
            // they call.

            std::unordered_set<const Func*> addls;

            for ( auto& cc : c.second ) {
                if ( cc == c.first )
                    // Don't loop over ourselves.
                    continue;

                // For each called function, pull up *its*
                // set of called functions.
                for ( auto& ccc : call_set[cc] ) {
                    // For each of those, if we don't
                    // already have it, add it.
                    if ( c.second.contains(ccc) )
                        // We already have it.
                        continue;

                    addls.insert(ccc);

                    if ( ccc != c.first )
                        // Non-recursive.
                        continue;

                    if ( report_recursive )
                        printf("%s is indirectly recursive, called by %s\n", c.first->GetName().c_str(),
                               cc->GetName().c_str());

                    non_recursive_funcs.erase(c.first);
                    non_recursive_funcs.erase(cc);
                }
            }

            if ( addls.size() > 0 ) {
                did_addition = true;

                for ( auto& a : addls )
                    c.second.insert(a);
            }
        }
    }

    for ( auto& f : funcs ) {
        if ( f.ShouldSkip() )
            continue;

        const auto& func_ptr = f.FuncPtr();
        const auto& func = func_ptr.get();
        const auto& body = f.Body();

        // Candidates are non-event, non-hook, non-recursive,
        // non-compiled functions ...
        if ( func->Flavor() != FUNC_FLAVOR_FUNCTION )
            continue;

        if ( ! non_recursive_funcs.contains(func) )
            continue;

        if ( ! is_ZAM_compilable(f.Profile()) )
            continue;

        inline_ables[func] = f.Profile();
    }

    if ( ! analysis_options.no_eh_coalescence )
        CoalesceEventHandlers();

    for ( auto& f : funcs )
        if ( f.ShouldAnalyze() )
            InlineFunction(&f);
}

void Inliner::CoalesceEventHandlers() {
    std::unordered_map<ScriptFunc*, size_t> event_handlers;
    BodyInfo body_to_info;
    for ( size_t i = 0U; i < funcs.size(); ++i ) {
        auto& f = funcs[i];
        if ( ! f.ShouldAnalyze() )
            continue;

        auto& func_ptr = f.FuncPtr();
        const auto& func = func_ptr.get();
        const auto& func_type = func->GetType();

        if ( func_type->AsFuncType()->Flavor() != FUNC_FLAVOR_EVENT )
            continue;

        // Special-case: zeek_init both has tons of event handlers (even
        // with -b), such that it inevitably blows out the inlining budget,
        // *and* only runs once, such that even if we could inline it, if
        // it takes more time to compile it than to just run it via the
        // interpreter, it's a lose.
        static std::string zeek_init_name = "zeek_init";
        if ( func->GetName() == zeek_init_name )
            continue;

        const auto& body = f.Body();

        if ( func->GetKind() == Func::SCRIPT_FUNC && func->GetBodies().size() > 1 ) {
            ++event_handlers[func];
            ASSERT(! body_to_info.contains(body.get()));
            body_to_info[body.get()] = i;
        }
    }

    for ( auto& e : event_handlers ) {
        auto func = e.first;
        auto& bodies = func->GetBodies();
        if ( bodies.size() != e.second )
            // It's potentially unsound to inline some-but-not-all event
            // handlers, because doing so may violate &priority's. We
            // could do the work of identifying such instances and only
            // skipping those, but given that ZAM is feature-complete
            // the mismatch here should only arise when using restrictions
            // like --optimize-file, which likely aren't the common case.
            continue;

        CoalesceEventHandlers({NewRef{}, func}, bodies, body_to_info);
    }
}

void Inliner::CoalesceEventHandlers(ScriptFuncPtr func, const std::vector<Func::Body>& bodies,
                                    const BodyInfo& body_to_info) {
    // We pattern the new (alternate) body off of the first body.
    auto& b0 = func->GetBodies()[0].stmts;
    auto merged_body = with_location_of(make_intrusive<StmtList>(), b0);
    auto oi = merged_body->GetOptInfo();

    auto& params = func->GetType()->Params();
    auto nparams = params->NumFields();
    size_t init_frame_size = static_cast<size_t>(nparams);

    PreInline(oi, init_frame_size);

    auto b0_info = body_to_info.find(b0.get());
    ASSERT(b0_info != body_to_info.end());
    auto& info0 = funcs[b0_info->second];
    auto& scope0 = info0.Scope();
    auto& vars = scope0->OrderedVars();

    // We need to create a new Scope. Otherwise, when inlining the first
    // body the analysis of identifiers gets confused regarding whether
    // a given identifier represents the outer instance or the inner.
    auto empty_attrs = std::make_unique<std::vector<AttrPtr>>();
    push_scope(scope0->GetID(), std::move(empty_attrs));

    std::vector<IDPtr> param_ids;

    for ( auto i = 0; i < nparams; ++i ) {
        auto& vi = vars[i];
        // We use a special scope name so that when debugging issues we can
        // see that a given variable came from coalescing event handlers.
        auto p = install_ID(vi->Name(), "<event>", false, false);
        p->SetType(vi->GetType());
        param_ids.push_back(std::move(p));
    }

    auto new_scope = pop_scope();

    // Build up the calling arguments.
    auto args = with_location_of(make_intrusive<ListExpr>(), b0);
    for ( auto& p : param_ids )
        args->Append(with_location_of(make_intrusive<NameExpr>(p), b0));

    for ( auto& b : bodies ) {
        auto bp = b.stmts;
        auto bi_find = body_to_info.find(bp.get());
        ASSERT(bi_find != body_to_info.end());
        auto& bi = funcs[bi_find->second];
        auto ie = DoInline(func, bp, args, bi.Scope(), bi.Profile());

        if ( ! ie )
            // Failure presumably occurred due to hitting the maximum
            // AST complexity for inlining. We can give up by simply
            // returning, as at this point we haven't made any actual
            // changes other than the function's scope.
            return;

        auto ie_s = with_location_of(make_intrusive<ExprStmt>(ie), bp);
        merged_body->Stmts().emplace_back(std::move(ie_s));
    }

    auto inlined_func = make_intrusive<CoalescedScriptFunc>(merged_body, new_scope, func);
    inlined_func->SetScope(new_scope);

    // Replace the function for that EventHandler with the delegating one.
    auto* eh = event_registry->Lookup(func->GetName());
    ASSERT(eh);
    eh->SetFunc(inlined_func);

    // Likewise, replace the value of the identifier.
    auto fid = lookup_ID(func->GetName().c_str(), GLOBAL_MODULE_NAME, false, false, false);
    ASSERT(fid);
    fid->SetVal(make_intrusive<FuncVal>(inlined_func));

    PostInline(oi, inlined_func);

    // We don't need to worry about event groups because the CoalescedScriptFunc
    // wrapper checks at run-time for whether any handlers have been disabled,
    // and if so skips coalesced execution.
    Func::Body body{.stmts = merged_body};
    funcs.emplace_back(inlined_func, new_scope, std::move(body));

    auto pf = std::make_shared<ProfileFunc>(inlined_func.get(), merged_body, true);
    funcs.back().SetProfile(std::move(pf));
}

void Inliner::InlineFunction(FuncInfo* f) {
    auto oi = f->Body()->GetOptInfo();
    PreInline(oi, f->Scope()->Length());
    f->Body()->Inline(this);
    PostInline(oi, f->FuncPtr());
}

void Inliner::PreInline(StmtOptInfo* oi, size_t frame_size) {
    max_inlined_frame_size = 0;
    curr_frame_size = frame_size;
    num_stmts = oi->num_stmts;
    num_exprs = oi->num_exprs;
}

void Inliner::PostInline(StmtOptInfo* oi, ScriptFuncPtr f) {
    oi->num_stmts = num_stmts;
    oi->num_exprs = num_exprs;

    int new_frame_size = curr_frame_size + max_inlined_frame_size;

    if ( new_frame_size > f->FrameSize() )
        f->SetFrameSize(new_frame_size);
}

ExprPtr Inliner::CheckForInlining(CallExprPtr c) {
    auto f = c->Func();

    if ( f->Tag() != EXPR_NAME )
        // We don't inline indirect calls.
        return c;

    auto n = f->AsNameExpr();
    auto func = n->Id();

    if ( ! func->IsGlobal() )
        return c;

    const auto& func_v = func->GetVal();
    if ( ! func_v )
        return c;

    auto function = func_v->AsFuncVal()->AsFuncPtr();

    if ( function->GetKind() != Func::SCRIPT_FUNC )
        return c;

    auto func_vf = cast_intrusive<ScriptFunc>(function);

    auto ia = inline_ables.find(func_vf.get());
    if ( ia == inline_ables.end() )
        return c;

    if ( c->IsInWhen() ) {
        // Don't inline these, as doing so requires propagating
        // the in-when attribute to the inlined function body.
        skipped_inlining.insert(func_vf.get());
        return c;
    }

    // Check for mismatches in argument count due to single-arg-of-type-any
    // loophole used for variadic BiFs.  (The issue isn't calls to the
    // BiFs, which won't happen here, but instead to script functions that
    // are misusing/abusing the loophole.)
    if ( function->GetType()->Params()->NumFields() == 1 && c->Args()->Exprs().size() != 1 ) {
        skipped_inlining.insert(func_vf.get());
        return c;
    }

    // We're going to inline the body, unless it's too large.
    auto body = func_vf->GetBodies()[0].stmts; // there's only 1 body
    auto scope = func_vf->GetScope();
    auto ie = DoInline(func_vf, body, c->ArgsPtr(), scope, ia->second);

    if ( ie ) {
        ie->SetLocationInfo(c->GetLocationInfo());
        did_inline.insert(func_vf.get());
    }

    return ie;
}

ExprPtr Inliner::DoInline(ScriptFuncPtr sf, StmtPtr body, ListExprPtr args, ScopePtr scope, const ProfileFunc* pf) {
    // Inline the body, unless it's too large.
    auto oi = body->GetOptInfo();

    if ( num_stmts + oi->num_stmts + num_exprs + oi->num_exprs > MAX_INLINE_SIZE ) {
        skipped_inlining.insert(sf.get());
        return nullptr; // signals "stop inlining"
    }

    num_stmts += oi->num_stmts;
    num_exprs += oi->num_exprs;

    auto body_dup = body->Duplicate();
    body_dup->GetOptInfo()->num_stmts = oi->num_stmts;
    body_dup->GetOptInfo()->num_exprs = oi->num_exprs;

    // Getting the names of the parameters is tricky.  It's tempting
    // to take them from the function's type declaration, but alas
    // Zeek allows forward-declaring a function with one set of parameter
    // names and then defining a later instance of it with different
    // names, as long as the types match.  So we have to glue together
    // the type declaration, which gives us the number of parameters,
    // with the scope, which gives us all the variables declared in
    // the function, *using the knowledge that the parameters are
    // declared first*.
    auto& vars = scope->OrderedVars();
    int nparam = sf->GetType()->Params()->NumFields();

    std::vector<IDPtr> params;
    std::vector<bool> param_is_modified;

    for ( int i = 0; i < nparam; ++i ) {
        auto& vi = vars[i];
        params.emplace_back(vi);
        param_is_modified.emplace_back((pf->Assignees().contains(vi)));
    }

    // Recursively inline the body.  This is safe to do because we've
    // ensured there are no recursive loops ... but we have to be
    // careful in accounting for the frame sizes.
    int frame_size = sf->FrameSize();

    int hold_curr_frame_size = curr_frame_size;
    curr_frame_size = frame_size;

    int hold_max_inlined_frame_size = max_inlined_frame_size;
    max_inlined_frame_size = 0;

    body_dup->Inline(this);

    curr_frame_size = hold_curr_frame_size;

    int new_frame_size = frame_size + max_inlined_frame_size;
    if ( new_frame_size > hold_max_inlined_frame_size )
        max_inlined_frame_size = new_frame_size;
    else
        max_inlined_frame_size = hold_max_inlined_frame_size;

    auto t = scope->GetReturnType();

    ASSERT(params.size() == args->Exprs().size());
    return with_location_of(make_intrusive<InlineExpr>(sf, args, params, param_is_modified, body_dup, curr_frame_size,
                                                       t),
                            body);
}

} // namespace zeek::detail
