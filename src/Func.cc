
// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Func.h"

#include "zeek/zeek-config.h"

#include <broker/error.hh>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <ranges>

// Most of these includes are needed for code included from bif files.
#include "zeek/Base64.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventTrace.h"
#include "zeek/Expr.h"
#include "zeek/File.h"
#include "zeek/Frame.h"
#include "zeek/NetVar.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Scope.h"
#include "zeek/ScriptProfile.h"
#include "zeek/Stats.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"
#include "zeek/Var.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/iosource/PktDumper.h"
#include "zeek/iosource/PktSrc.h"
#include "zeek/module_util.h"
#include "zeek/plugin/Manager.h"
#include "zeek/session/Manager.h"

// Ignore clang-format's reordering of include files here so that it doesn't
// break what symbols are available when, which keeps the build from breaking.
// clang-format off
#include "zeek.bif.func_h"
#include "communityid.bif.func_h"
#include "stats.bif.func_h"
#include "reporter.bif.func_h"
#include "strings.bif.func_h"
#include "option.bif.func_h"
#include "supervisor.bif.func_h"
#include "packet_analysis.bif.func_h"
#include "CPP-load.bif.func_h"
#include "mmdb.bif.func_h"
#include "telemetry_functions.bif.func_h"

#include "zeek.bif.func_def"
#include "communityid.bif.func_def"
#include "stats.bif.func_def"
#include "reporter.bif.func_def"
#include "strings.bif.func_def"
#include "option.bif.func_def"
#include "supervisor.bif.func_def"
#include "packet_analysis.bif.func_def"
#include "CPP-load.bif.func_def"
#include "mmdb.bif.func_def"
#include "telemetry_functions.bif.func_def"
// clang-format on

extern RETSIGTYPE sig_handler(int signo);

namespace zeek::detail {
std::vector<CallInfo> call_stack;
bool did_builtin_init = false;
std::vector<void (*)()> bif_initializers;
static const std::pair<bool, zeek::ValPtr> empty_hook_result(false, nullptr);
} // namespace zeek::detail

namespace zeek {

std::string render_call_stack() {
    std::string rval;
    int lvl = 0;

    if ( ! detail::call_stack.empty() )
        rval += "| ";

    for ( auto& ci : std::ranges::reverse_view(detail::call_stack) ) {
        if ( lvl > 0 )
            rval += " | ";

        const auto& name = ci.func->GetName();
        std::string arg_desc;

        for ( const auto& arg : ci.args ) {
            ODesc d;
            d.SetShort();
            arg->Describe(&d);

            if ( ! arg_desc.empty() )
                arg_desc += ", ";

            arg_desc += d.Description();
        }

        rval += util::fmt("#%d %s(%s)", lvl, name.c_str(), arg_desc.data());

        if ( ci.call ) {
            auto loc = ci.call->GetLocationInfo();
            rval += util::fmt(" at %s:%d", loc->FileName(), loc->FirstLine());
        }

        ++lvl;
    }

    if ( ! detail::call_stack.empty() )
        rval += " |";

    return rval;
}

void Func::AddBody(const detail::FunctionIngredients& ingr, detail::StmtPtr new_body) {
    if ( ! new_body )
        new_body = ingr.Body();

    AddBody(new_body, ingr.Inits(), ingr.FrameSize(), ingr.Priority(), ingr.Groups());
}

void Func::AddBody(detail::StmtPtr new_body, const std::vector<detail::IDPtr>& new_inits, size_t new_frame_size,
                   int priority) {
    std::set<EventGroupPtr> groups;
    AddBody(std::move(new_body), new_inits, new_frame_size, priority, groups);
}

void Func::AddBody(detail::StmtPtr new_body, size_t new_frame_size) {
    std::vector<detail::IDPtr> no_inits;
    std::set<EventGroupPtr> no_groups;
    AddBody(std::move(new_body), no_inits, new_frame_size, 0, no_groups);
}

void Func::AddBody(detail::StmtPtr /* new_body */, const std::vector<detail::IDPtr>& /* new_inits */,
                   size_t /* new_frame_size */, int /* priority */, const std::set<EventGroupPtr>& /* groups */) {
    Internal("Func::AddBody called");
}

void Func::AddBody(std::function<void(const zeek::Args&, detail::StmtFlowType&)> body, int priority) {
    auto stmt = zeek::make_intrusive<detail::StdFunctionStmt>(std::move(body));
    AddBody(stmt, {}, priority);
}

void Func::SetScope(detail::ScopePtr newscope) { scope = std::move(newscope); }

FuncPtr Func::DoClone() {
    // By default, ok just to return a reference. Func does not have any state
    // that is different across instances.
    return {NewRef{}, this};
}

void Func::DescribeDebug(ODesc* d, const Args* args) const {
    d->Add(GetName().c_str());

    if ( args ) {
        d->Add("(");
        const auto& func_args = GetType()->Params();
        auto num_fields = static_cast<size_t>(func_args->NumFields());

        for ( auto i = 0u; i < args->size(); ++i ) {
            // Handle varargs case (more args than formals).
            if ( i >= num_fields ) {
                d->Add("vararg");
                int va_num = i - num_fields;
                d->Add(va_num);
            }
            else
                d->Add(func_args->FieldName(i));

            d->Add(" = '");
            (*args)[i]->Describe(d);

            if ( i < args->size() - 1 )
                d->Add("', ");
            else
                d->Add("'");
        }

        d->Add(")");
    }
}

detail::TraversalCode Func::Traverse(detail::TraversalCallback* cb) const {
    // FIXME: Make a fake scope for builtins?
    auto old_scope = cb->current_scope;
    cb->current_scope = scope;

    detail::TraversalCode tc = cb->PreFunction(this);
    HANDLE_TC_STMT_PRE(tc);

    // FIXME: Traverse arguments to builtin functions, too.
    if ( kind == SCRIPT_FUNC && scope ) {
        tc = scope->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);

        for ( const auto& body : bodies ) {
            tc = body.stmts->Traverse(cb);
            HANDLE_TC_STMT_PRE(tc);
        }
    }

    tc = cb->PostFunction(this);

    cb->current_scope = old_scope;
    HANDLE_TC_STMT_POST(tc);
}

void Func::CopyStateInto(Func* other) const {
    other->bodies = bodies;
    other->scope = scope;
    other->kind = kind;

    other->type = type;

    other->name = name;
}

void Func::CheckPluginResult(bool handled, const ValPtr& hook_result, FunctionFlavor flavor) const {
    // Helper function factoring out this code from ScriptFunc:Call() for
    // better readability.

    if ( ! handled ) {
        if ( hook_result )
            reporter->InternalError("plugin set processed flag to false but actually returned a value");

        // The plugin result hasn't been processed yet (read: fall
        // into ::Call method).
        return;
    }

    switch ( flavor ) {
        case FUNC_FLAVOR_EVENT:
            if ( hook_result )
                reporter->InternalError("plugin returned non-void result for event %s", GetName().c_str());

            break;

        case FUNC_FLAVOR_HOOK:
            if ( hook_result->GetType()->Tag() != TYPE_BOOL )
                reporter->InternalError("plugin returned non-bool for hook %s", GetName().c_str());

            break;

        case FUNC_FLAVOR_FUNCTION: {
            const auto& yt = GetType()->Yield();

            if ( (! yt) || yt->Tag() == TYPE_VOID ) {
                if ( hook_result )
                    reporter->InternalError("plugin returned non-void result for void method %s", GetName().c_str());
            }

            else if ( hook_result && hook_result->GetType()->Tag() != yt->Tag() && yt->Tag() != TYPE_ANY ) {
                reporter->InternalError("plugin returned wrong type (got %d, expecting %d) for %s",
                                        hook_result->GetType()->Tag(), yt->Tag(), GetName().c_str());
            }

            break;
        }
    }
}

namespace detail {

ScriptFunc::ScriptFunc(const IDPtr& arg_id) : Func(SCRIPT_FUNC) {
    name = arg_id->Name();
    type = arg_id->GetType<zeek::FuncType>();
    frame_size = 0;
}

ScriptFunc::ScriptFunc(std::string _name, FuncTypePtr ft, std::vector<StmtPtr> bs, std::vector<int> priorities) {
    name = std::move(_name);
    frame_size = ft->ParamList()->GetTypes().size();
    type = std::move(ft);

    auto n = bs.size();
    ASSERT(n == priorities.size());

    for ( auto i = 0u; i < n; ++i ) {
        Body b;
        b.stmts = std::move(bs[i]);
        b.priority = priorities[i];
        bodies.push_back(std::move(b));
    }

    std::ranges::stable_sort(bodies, std::ranges::greater(), &Body::priority);

    if ( ! bodies.empty() )
        current_body = bodies[0];
}

ScriptFunc::~ScriptFunc() {
    if ( captures_vec ) {
        auto& cvec = *captures_vec;
        auto& captures = *type->GetCaptures();
        for ( auto i = 0u; i < captures.size(); ++i )
            if ( captures[i].IsManaged() )
                ZVal::DeleteManagedType(cvec[i]);
    }

    delete captures_frame;
    delete captures_offset_mapping;
}

bool ScriptFunc::IsPure() const {
    return std::ranges::all_of(bodies, [](const Body& b) { return b.stmts->IsPure(); });
}

ValPtr ScriptFunc::Invoke(zeek::Args* args, Frame* parent) const {
    auto [handled, hook_result] =
        PLUGIN_HOOK_WITH_RESULT(HOOK_CALL_FUNCTION, HookCallFunction(this, parent, args), empty_hook_result);

    CheckPluginResult(handled, hook_result, Flavor());

    if ( handled )
        return hook_result;

    if ( bodies.empty() ) {
        // Can only happen for events and hooks.
        assert(Flavor() == FUNC_FLAVOR_EVENT || Flavor() == FUNC_FLAVOR_HOOK);
        return Flavor() == FUNC_FLAVOR_HOOK ? val_mgr->True() : nullptr;
    }

    auto f = make_intrusive<Frame>(frame_size, this, args);

    // Hand down any trigger.
    if ( parent ) {
        f->SetTrigger({NewRef{}, parent->GetTrigger()});
        f->SetTriggerAssoc(parent->GetTriggerAssoc());
    }

    const CallExpr* call_expr = parent ? parent->GetCall() : nullptr;
    call_stack.emplace_back(CallInfo{call_expr, this, *args});

    // If a script function is ever invoked with more arguments than it has
    // parameters log an error and return. Most likely a "variadic function"
    // that only has a single any parameter and is excluded from static type
    // checking is involved. This should otherwise not be possible to hit.
    auto num_params = static_cast<size_t>(GetType()->Params()->NumFields());
    if ( args->size() > num_params ) {
        emit_builtin_exception("too many arguments for function call");
        return nullptr;
    }

    if ( event_trace_mgr && Flavor() == FUNC_FLAVOR_EVENT )
        event_trace_mgr->StartEvent(this, args);

    StmtFlowType flow = FLOW_NEXT;
    ValPtr result;

    for ( const auto& body : bodies ) {
        if ( body.disabled )
            continue;

        // Fill in the rest of the frame with the function's arguments.
        for ( auto j = 0u; j < args->size(); ++j ) {
            const auto& arg = (*args)[j];

            if ( f->GetElement(j) != arg )
                // Either not yet set, or somebody reassigned the frame slot.
                f->SetElement(j, arg);
        }

        if ( spm )
            spm->StartInvocation(this, body.stmts);

        f->Reset(args->size());

        try {
            result = body.stmts->Exec(f.get(), flow);
        }

        catch ( InterpreterException& e ) {
            // Already reported, but now determine whether to unwind further.
            if ( Flavor() == FUNC_FLAVOR_FUNCTION ) {
                call_stack.pop_back();
                // Result not set b/c exception was thrown
                throw;
            }

            // Continue exec'ing remaining bodies of hooks/events.
            continue;
        }

        if ( spm )
            spm->EndInvocation();

        if ( f->HasDelayed() ) {
            assert(! result);
            assert(parent);
            parent->SetDelayed();
            break;
        }

        if ( Flavor() == FUNC_FLAVOR_HOOK ) {
            // Ignore any return values of hook bodies, final return value
            // depends on whether a body returns as a result of break statement.
            result = nullptr;

            if ( flow == FLOW_BREAK ) {
                // Short-circuit execution of remaining hook handler bodies.
                result = val_mgr->False();
                break;
            }
        }
    }

    call_stack.pop_back();

    if ( Flavor() == FUNC_FLAVOR_HOOK ) {
        if ( ! result )
            result = val_mgr->True();
    }

    else if ( event_trace_mgr && Flavor() == FUNC_FLAVOR_EVENT )
        event_trace_mgr->EndEvent(this, args);

    // Warn if the function returns something, but we returned from
    // the function without an explicit return, or without a value.
    else if ( GetType()->Yield() && GetType()->Yield()->Tag() != TYPE_VOID && ! GetType()->ExpressionlessReturnOkay() &&
              (flow != FLOW_RETURN /* we fell off the end */ || ! result /* explicit return with no result */) &&
              ! f->HasDelayed() )
        reporter->Warning("non-void function returning without a value: %s", GetName().c_str());

    return result;
}

void ScriptFunc::CreateCaptures(Frame* f) {
    const auto& captures = type->GetCaptures();

    if ( ! captures )
        return;

    // Create *either* a private Frame to hold the values of captured
    // variables, and a mapping from those variables to their offsets
    // in the Frame; *or* a ZVal frame if this script has a ZAM-compiled
    // body.
    ASSERT(bodies.size() == 1);

    if ( bodies[0].stmts->Tag() == STMT_ZAM )
        captures_vec = std::make_unique<std::vector<ZVal>>();
    else {
        delete captures_frame;
        delete captures_offset_mapping;
        captures_frame = new Frame(captures->size(), this, nullptr);
        captures_offset_mapping = new OffsetMap;
    }

    int offset = 0;
    for ( const auto& c : *captures ) {
        auto v = f->GetElementByID(c.Id());

        if ( v ) {
            if ( c.IsDeepCopy() || ! v->Modifiable() )
                v = v->Clone();

            if ( captures_vec )
                // Don't use v->GetType() here, as that might
                // be "any" and we need to convert.
                captures_vec->push_back(ZVal(v, c.Id()->GetType()));
            else
                captures_frame->SetElement(offset, std::move(v));
        }

        else if ( captures_vec )
            captures_vec->push_back(ZVal());

        if ( ! captures_vec )
            captures_offset_mapping->insert_or_assign(c.Id()->Name(), offset);

        ++offset;
    }
}

void ScriptFunc::CreateCaptures(std::unique_ptr<std::vector<ZVal>> cvec) {
    const auto& captures = *type->GetCaptures();

    ASSERT(cvec->size() == captures.size());
    ASSERT(bodies.size() == 1 && bodies[0].stmts->Tag() == STMT_ZAM);

    captures_vec = std::move(cvec);

    auto n = captures.size();
    for ( auto i = 0U; i < n; ++i ) {
        auto& c_i = captures[i];
        auto& cv_i = (*captures_vec)[i];

        if ( c_i.IsDeepCopy() ) {
            auto& t = c_i.Id()->GetType();
            auto new_cv_i = cv_i.ToVal(t)->Clone();
            if ( c_i.IsManaged() )
                ZVal::DeleteManagedType(cv_i);

            cv_i = ZVal(std::move(new_cv_i), t);
        }
    }
}

void ScriptFunc::SetCapturesVec(std::unique_ptr<std::vector<ZVal>> cv) { captures_vec = std::move(cv); }

void ScriptFunc::SetCaptures(Frame* f) {
    const auto& captures = type->GetCaptures();
    ASSERT(captures);

    delete captures_frame;
    delete captures_offset_mapping;
    captures_frame = f;
    captures_offset_mapping = new OffsetMap;

    int offset = 0;
    for ( const auto& c : *captures ) {
        captures_offset_mapping->insert_or_assign(c.Id()->Name(), offset);
        ++offset;
    }
}

void ScriptFunc::AddBody(StmtPtr new_body, const std::vector<IDPtr>& new_inits, size_t new_frame_size, int priority,
                         const std::set<EventGroupPtr>& groups) {
    if ( new_frame_size > frame_size )
        frame_size = new_frame_size;

    auto num_args = static_cast<size_t>(GetType()->Params()->NumFields());

    if ( num_args > frame_size )
        frame_size = num_args;

    new_body = AddInits(std::move(new_body), new_inits);

    if ( Flavor() == FUNC_FLAVOR_FUNCTION ) {
        // For functions, we replace the old body with the new one.
        assert(bodies.size() <= 1);
        bodies.clear();
    }

    current_body = Body{.stmts = new_body, .groups = {groups.begin(), groups.end()}, .priority = priority};

    bodies.push_back(current_body);
    std::ranges::stable_sort(bodies, std::ranges::greater(), &Body::priority);
}

void ScriptFunc::ReplaceBody(const StmtPtr& old_body, StmtPtr new_body) {
    bool found_it = false;

    for ( auto body = bodies.begin(); body != bodies.end(); ++body )
        if ( body->stmts.get() == old_body.get() ) {
            if ( new_body )
                body->stmts = new_body;
            else
                bodies.erase(body);

            found_it = true;
            current_body = *body;
            break;
        }
}

bool ScriptFunc::DeserializeCaptures(BrokerListView data) {
    auto result = Frame::Unserialize(data);

    ASSERT(result.first);

    auto& f = result.second;

    if ( bodies[0].stmts->Tag() == STMT_ZAM ) {
        auto& captures = *type->GetCaptures();
        int n = f->FrameSize();

        ASSERT(captures.size() == static_cast<size_t>(n));

        auto cvec = std::make_unique<std::vector<ZVal>>();

        for ( int i = 0; i < n; ++i ) {
            auto& f_i = f->GetElement(i);
            cvec->push_back(ZVal(f_i, captures[i].Id()->GetType()));
        }

        CreateCaptures(std::move(cvec));
    }

    else
        SetCaptures(f.release());

    return true;
}

FuncPtr ScriptFunc::DoClone() {
    // ScriptFunc could hold a closure. In this case a clone of it must
    // store a copy of this closure.
    //
    // We don't use make_intrusive<> directly because we're accessing
    // a protected constructor.
    auto other = IntrusivePtr{AdoptRef{}, new ScriptFunc()};

    CopyStateInto(other.get());

    other->frame_size = frame_size;
    other->outer_ids = outer_ids;

    if ( captures_frame ) {
        other->captures_frame = captures_frame->Clone();
        other->captures_offset_mapping = new OffsetMap;
        *other->captures_offset_mapping = *captures_offset_mapping;
    }

    if ( captures_vec ) {
        auto cv_i = captures_vec->begin();
        other->captures_vec = std::make_unique<std::vector<ZVal>>();
        for ( auto& c : *type->GetCaptures() ) {
            // Need to clone cv_i.
            auto& t_i = c.Id()->GetType();
            auto cv_i_val = cv_i->ToVal(t_i)->Clone();
            other->captures_vec->push_back(ZVal(std::move(cv_i_val), t_i));
            ++cv_i;
        }
    }

    return other;
}

std::optional<BrokerData> ScriptFunc::SerializeCaptures() const {
    if ( captures_vec ) {
        auto& cv = *captures_vec;
        auto& captures = *type->GetCaptures();
        int n = captures_vec->size();
        auto temp_frame = make_intrusive<Frame>(n, this, nullptr);

        for ( int i = 0; i < n; ++i ) {
            auto c_i = cv[i].ToVal(captures[i].Id()->GetType());
            temp_frame->SetElement(i, c_i);
        }

        return temp_frame->Serialize();
    }

    if ( captures_frame )
        return captures_frame->Serialize();

    // No captures, return an empty vector.
    return BrokerListBuilder{}.Build();
}

void ScriptFunc::Describe(ODesc* d) const {
    d->Add(GetName().c_str());
    d->AddSP(":");
    type->Describe(d);

    d->NL();
    d->AddCount(frame_size);
    for ( const auto& body : bodies ) {
        body.stmts->AccessStats(d);
        body.stmts->Describe(d);
    }
}

StmtPtr ScriptFunc::AddInits(StmtPtr body, const std::vector<IDPtr>& inits) {
    if ( inits.empty() )
        return body;

    auto stmt_series = with_location_of(make_intrusive<StmtList>(), body);
    auto init = with_location_of(make_intrusive<InitStmt>(inits), body);

    stmt_series->Stmts().emplace_back(std::move(init));
    stmt_series->Stmts().emplace_back(std::move(body));

    return stmt_series;
}

BuiltinFunc::BuiltinFunc(built_in_func arg_func, const char* arg_name, bool arg_is_pure) : Func(BUILTIN_FUNC) {
    func = arg_func;
    name = make_full_var_name(GLOBAL_MODULE_NAME, arg_name);
    is_pure = arg_is_pure;

    const auto& id = lookup_ID(GetName().c_str(), GLOBAL_MODULE_NAME, false);
    if ( ! id )
        reporter->InternalError("built-in function %s missing", GetName().c_str());
    if ( id->HasVal() )
        reporter->InternalError("built-in function %s multiply defined", GetName().c_str());

    type = id->GetType<FuncType>();
    id->SetVal(make_intrusive<FuncVal>(IntrusivePtr{NewRef{}, this}));
    id->SetConst();
}

bool BuiltinFunc::IsPure() const { return is_pure; }

ValPtr BuiltinFunc::Invoke(Args* args, Frame* parent) const {
    if ( spm )
        spm->StartInvocation(this);

    auto [handled, hook_result] =
        PLUGIN_HOOK_WITH_RESULT(HOOK_CALL_FUNCTION, HookCallFunction(this, parent, args), empty_hook_result);

    CheckPluginResult(handled, hook_result, FUNC_FLAVOR_FUNCTION);

    if ( handled ) {
        if ( spm )
            spm->EndInvocation();
        return hook_result;
    }

    const CallExpr* call_expr = parent ? parent->GetCall() : nullptr;
    call_stack.emplace_back(CallInfo{call_expr, this, *args});
    auto result = func(parent, args);
    call_stack.pop_back();

    if ( spm )
        spm->EndInvocation();

    return result;
}

void BuiltinFunc::Describe(ODesc* d) const {
    d->Add(GetName().c_str());
    d->AddCount(is_pure);
}

bool check_built_in_call(BuiltinFunc* f, CallExpr* call) {
    if ( f->TheFunc() != BifFunc::fmt_bif )
        return true;

    const ExprPList& args = call->Args()->Exprs();
    if ( args.length() == 0 ) {
        // Empty calls are allowed, since you can't just
        // use "print;" to get a blank line.
        return true;
    }

    const Expr* fmt_str_arg = args[0];
    if ( fmt_str_arg->GetType()->Tag() != TYPE_STRING ) {
        call->Error("first argument to util::fmt() needs to be a format string");
        return false;
    }

    auto fmt_str_val = fmt_str_arg->Eval(nullptr);

    if ( fmt_str_val ) {
        const char* fmt_str = fmt_str_val->AsStringVal()->CheckString();

        int num_fmt = 0;
        while ( *fmt_str ) {
            if ( *(fmt_str++) != '%' )
                continue;

            if ( ! *fmt_str ) {
                call->Error("format string ends with bare '%'");
                return false;
            }

            if ( *(fmt_str++) != '%' )
                // Not a "%%" escape.
                ++num_fmt;
        }

        if ( args.length() != num_fmt + 1 ) {
            call->Error("mismatch between format string to util::fmt() and number of arguments passed");
            return false;
        }
    }

    return true;
}

// Gets a function's priority from its Scope's attributes. Errors if it sees any
// problems.
static int get_func_priority(const std::vector<AttrPtr>& attrs) {
    int priority = 0;

    for ( const auto& a : attrs ) {
        if ( a->Tag() == ATTR_DEPRECATED || a->Tag() == ATTR_IS_USED || a->Tag() == ATTR_GROUP )
            continue;

        if ( a->Tag() != ATTR_PRIORITY ) {
            a->Error("illegal attribute for function body");
            continue;
        }

        auto v = a->GetExpr()->Eval(nullptr);

        if ( ! v ) {
            a->Error("cannot evaluate attribute expression");
            continue;
        }

        if ( ! IsIntegral(v->GetType()->Tag()) ) {
            a->Error("expression is not of integral type");
            continue;
        }

        priority = v->InternalInt();
    }

    return priority;
}

// Get a function's groups from its Scope's attributes. Errors if it sees any
// problems with the group tag.  get_func_priority() checks for illegal
// attributes, so we don't do this here.
static std::set<EventGroupPtr> get_func_groups(const std::vector<AttrPtr>& attrs) {
    std::set<EventGroupPtr> groups;

    for ( const auto& a : attrs ) {
        if ( a->Tag() != ATTR_GROUP )
            continue;

        auto v = a->GetExpr()->Eval(nullptr);

        if ( ! v ) {
            a->Error("cannot evaluate attribute expression");
            continue;
        }

        if ( ! IsString(v->GetType()->Tag()) ) {
            a->Error("expression is not of string type");
            continue;
        }

        auto group = event_registry->RegisterGroup(EventGroupKind::Attribute, v->AsStringVal()->ToStdStringView());
        groups.insert(std::move(group));
    }

    return groups;
}

FunctionIngredients::FunctionIngredients(ScopePtr _scope, StmtPtr _body, const std::string& module_name) {
    scope = std::move(_scope);
    body = std::move(_body);

    frame_size = scope->Length();
    inits = scope->GetInits();

    id = scope->GetID();

    const auto& attrs = scope->Attrs();

    if ( attrs ) {
        priority = get_func_priority(*attrs);

        groups = get_func_groups(*attrs);

        for ( const auto& a : *attrs )
            if ( a->Tag() == ATTR_IS_USED ) {
                // Associate this with the identifier, too.
                id->AddAttr(make_intrusive<Attr>(ATTR_IS_USED));
                break;
            }
    }
    else
        priority = 0;

    // Implicit module event groups for events and hooks.
    auto flavor = id->GetType<zeek::FuncType>()->Flavor();
    if ( flavor == FUNC_FLAVOR_EVENT || flavor == FUNC_FLAVOR_HOOK ) {
        auto module_group = event_registry->RegisterGroup(EventGroupKind::Module, module_name);
        groups.insert(std::move(module_group));
    }
}

zeek::RecordValPtr make_backtrace_element(std::string_view name, const VectorValPtr args,
                                          const zeek::detail::Location* loc) {
    static auto elem_type = id::find_type<RecordType>("BacktraceElement");
    static auto function_name_idx = elem_type->FieldOffset("function_name");
    static auto function_args_idx = elem_type->FieldOffset("function_args");
    static auto file_location_idx = elem_type->FieldOffset("file_location");
    static auto line_location_idx = elem_type->FieldOffset("line_location");

    auto elem = make_intrusive<RecordVal>(elem_type);
    elem->Assign(function_name_idx, name);
    elem->Assign(function_args_idx, args);

    if ( loc ) {
        elem->Assign(file_location_idx, loc->FileName());
        elem->Assign(line_location_idx, loc->FirstLine());
    }

    return elem;
}

zeek::VectorValPtr get_current_script_backtrace() {
    static auto backtrace_type = id::find_type<VectorType>("Backtrace");

    auto rval = make_intrusive<VectorVal>(backtrace_type);

    // The body of the following loop can wind up adding items to
    // the call stack (because MakeCallArgumentVector() evaluates
    // default arguments, which can in turn involve calls to script
    // functions), so we work from a copy of the current call stack
    // to prevent problems with iterator invalidation.
    auto cs_copy = zeek::detail::call_stack;

    for ( const auto& ci : std::ranges::reverse_view(cs_copy) ) {
        if ( ! ci.func )
            // This happens for compiled code.
            continue;

        const auto& params = ci.func->GetType()->Params();
        auto args = MakeCallArgumentVector(ci.args, params);

        auto elem =
            make_backtrace_element(ci.func->GetName(), std::move(args), ci.call ? ci.call->GetLocationInfo() : nullptr);
        rval->Append(std::move(elem));
    }

    return rval;
}

static void emit_builtin_error_common(const char* msg, Obj* arg, bool unwind) {
    auto emit = [=](const CallExpr* ce) {
        if ( ce ) {
            if ( unwind ) {
                if ( arg ) {
                    ODesc d;
                    arg->Describe(&d);
                    reporter->ExprRuntimeError(ce, "%s (%s), during call:", msg, d.Description());
                }
                else
                    reporter->ExprRuntimeError(ce, "%s", msg);
            }
            else
                ce->Error(msg, arg);
        }
        else {
            if ( arg ) {
                if ( unwind )
                    reporter->RuntimeError(arg->GetLocationInfo(), "%s", msg);
                else
                    arg->Error(msg);
            }
            else {
                if ( unwind )
                    reporter->RuntimeError(nullptr, "%s", msg);
                else
                    reporter->Error("%s", msg);
            }
        }
    };

    if ( call_stack.empty() ) {
        // Shouldn't happen unless someone (mistakenly) calls builtin_error()
        // from somewhere that's not even evaluating script-code.
        emit(nullptr);
        return;
    }

    auto last_call = call_stack.back();

    if ( call_stack.size() < 2 ) {
        // Don't need to check for wrapper function like "<module>::__<func>"
        emit(last_call.call);
        return;
    }

    auto starts_with_double_underscore = [](const std::string& name) -> bool {
        return name.size() > 2 && name[0] == '_' && name[1] == '_';
    };
    const std::string& last_func = last_call.func->GetName();

    auto pos = last_func.find_first_of("::");
    std::string wrapper_func;

    if ( pos == std::string::npos ) {
        if ( ! starts_with_double_underscore(last_func) ) {
            emit(last_call.call);
            return;
        }

        wrapper_func = last_func.substr(2);
    }
    else {
        auto module_name = last_func.substr(0, pos);
        auto func_name = last_func.substr(pos + 2);

        if ( ! starts_with_double_underscore(func_name) ) {
            emit(last_call.call);
            return;
        }

        wrapper_func = module_name + "::" + func_name.substr(2);
    }

    auto parent_call = call_stack[call_stack.size() - 2];
    const auto& parent_func = parent_call.func->GetName();

    if ( wrapper_func == parent_func )
        emit(parent_call.call);
    else
        emit(last_call.call);
}

void emit_builtin_exception(const char* msg) { emit_builtin_error_common(msg, nullptr, true); }

void emit_builtin_exception(const char* msg, const ValPtr& arg) { emit_builtin_error_common(msg, arg.get(), true); }

void emit_builtin_exception(const char* msg, Obj* arg) { emit_builtin_error_common(msg, arg, true); }

void init_primary_bifs() {
    if ( did_builtin_init )
        return;

    ProcStats = id::find_type<RecordType>("ProcStats");
    NetStats = id::find_type<RecordType>("NetStats");
    MatcherStats = id::find_type<RecordType>("MatcherStats");
    ConnStats = id::find_type<RecordType>("ConnStats");
    ReassemblerStats = id::find_type<RecordType>("ReassemblerStats");
    DNSStats = id::find_type<RecordType>("DNSStats");
    GapStats = id::find_type<RecordType>("GapStats");
    EventStats = id::find_type<RecordType>("EventStats");
    TimerStats = id::find_type<RecordType>("TimerStats");
    FileAnalysisStats = id::find_type<RecordType>("FileAnalysisStats");
    ThreadStats = id::find_type<RecordType>("ThreadStats");
    BrokerStats = id::find_type<RecordType>("BrokerStats");
    ReporterStats = id::find_type<RecordType>("ReporterStats");

    var_sizes = id::find_type("var_sizes")->AsTableType();

#include "CPP-load.bif.func_init"
#include "communityid.bif.func_init"
#include "mmdb.bif.func_init"
#include "option.bif.func_init"
#include "packet_analysis.bif.func_init"
#include "reporter.bif.func_init"
#include "stats.bif.func_init"
#include "strings.bif.func_init"
#include "supervisor.bif.func_init"
#include "telemetry_functions.bif.func_init"
#include "zeek.bif.func_init"

    init_builtin_types();
    did_builtin_init = true;
}

} // namespace detail

void emit_builtin_error(const char* msg) { zeek::detail::emit_builtin_error_common(msg, nullptr, false); }

void emit_builtin_error(const char* msg, const zeek::ValPtr& arg) {
    zeek::detail::emit_builtin_error_common(msg, arg.get(), false);
}

void emit_builtin_error(const char* msg, Obj* arg) { zeek::detail::emit_builtin_error_common(msg, arg, false); }

} // namespace zeek
