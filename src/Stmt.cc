// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Stmt.h"

#include "zeek/CompHash.h"
#include "zeek/Debug.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventTrace.h"
#include "zeek/Expr.h"
#include "zeek/File.h"
#include "zeek/Frame.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Traverse.h"
#include "zeek/Trigger.h"
#include "zeek/Var.h"
#include "zeek/logging/Manager.h"
#include "zeek/logging/logging.bif.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/StmtOptInfo.h"

namespace zeek::detail {

const char* stmt_name(StmtTag t) {
    static const char* stmt_names[int(NUM_STMTS)] = {
        "alarm", // Does no longer exist, but kept for keeping enums consistent.
        "print",
        "event",
        "expr",
        "if",
        "when",
        "switch",
        "for",
        "next",
        "break",
        "return",
        "list",
        "bodylist",
        "<init>",
        "fallthrough",
        "while",
        "catch-return",
        "check-any-length",
        "compiled-C++",
        "ZAM",
        "null",
        "assert",
        "extern",
        "std-function",
    };

    return stmt_names[int(t)];
}

int Stmt::num_stmts = 0;

Stmt::Stmt(StmtTag arg_tag) {
    tag = arg_tag;
    breakpoint_count = 0;
    last_access = 0;
    access_count = 0;

    opt_info = new StmtOptInfo();

    SetLocationInfo(&start_location, &end_location);

    ++num_stmts;
}

Stmt::~Stmt() { delete opt_info; }

StmtList* Stmt::AsStmtList() {
    CHECK_TAG(tag, STMT_LIST, "Stmt::AsStmtList", stmt_name)
    return (StmtList*)this;
}

const StmtList* Stmt::AsStmtList() const {
    CHECK_TAG(tag, STMT_LIST, "Stmt::AsStmtList", stmt_name)
    return (const StmtList*)this;
}

ForStmt* Stmt::AsForStmt() {
    CHECK_TAG(tag, STMT_FOR, "Stmt::AsForStmt", stmt_name)
    return (ForStmt*)this;
}

const ForStmt* Stmt::AsForStmt() const {
    CHECK_TAG(tag, STMT_FOR, "Stmt::AsForStmt", stmt_name)
    return (const ForStmt*)this;
}

const InitStmt* Stmt::AsInitStmt() const {
    CHECK_TAG(tag, STMT_INIT, "Stmt::AsInitStmt", stmt_name)
    return (const InitStmt*)this;
}

const IfStmt* Stmt::AsIfStmt() const {
    CHECK_TAG(tag, STMT_IF, "Stmt::AsIfStmt", stmt_name)
    return (const IfStmt*)this;
}

const WhileStmt* Stmt::AsWhileStmt() const {
    CHECK_TAG(tag, STMT_WHILE, "Stmt::AsWhileStmt", stmt_name)
    return (const WhileStmt*)this;
}

const WhenStmt* Stmt::AsWhenStmt() const {
    CHECK_TAG(tag, STMT_WHEN, "Stmt::AsWhenStmt", stmt_name)
    return (const WhenStmt*)this;
}

const SwitchStmt* Stmt::AsSwitchStmt() const {
    CHECK_TAG(tag, STMT_SWITCH, "Stmt::AsSwitchStmt", stmt_name)
    return (const SwitchStmt*)this;
}

const ExprStmt* Stmt::AsExprStmt() const {
    CHECK_TAG(tag, STMT_EXPR, "Stmt::AsExprStmt", stmt_name)
    return (const ExprStmt*)this;
}

const PrintStmt* Stmt::AsPrintStmt() const {
    CHECK_TAG(tag, STMT_PRINT, "Stmt::AsPrintStmt", stmt_name)
    return (const PrintStmt*)this;
}

const CatchReturnStmt* Stmt::AsCatchReturnStmt() const {
    CHECK_TAG(tag, STMT_CATCH_RETURN, "Stmt::AsCatchReturnStmt", stmt_name)
    return (const CatchReturnStmt*)this;
}

const ReturnStmt* Stmt::AsReturnStmt() const {
    CHECK_TAG(tag, STMT_RETURN, "Stmt::AsReturnStmt", stmt_name)
    return (const ReturnStmt*)this;
}

const NullStmt* Stmt::AsNullStmt() const {
    CHECK_TAG(tag, STMT_NULL, "Stmt::AsNullStmt", stmt_name)
    return (const NullStmt*)this;
}

const AssertStmt* Stmt::AsAssertStmt() const {
    CHECK_TAG(tag, STMT_ASSERT, "Stmt::AsAssertStmt", stmt_name)
    return (const AssertStmt*)this;
}

bool Stmt::SetLocationInfo(const Location* start, const Location* end) {
    if ( ! Obj::SetLocationInfo(start, end) )
        return false;

    // Update the Filemap of line number -> statement mapping for
    // breakpoints (Debug.h).
    auto map_iter = g_dbgfilemaps.find(location->filename);
    if ( map_iter == g_dbgfilemaps.end() )
        return false;

    Filemap& map = *(map_iter->second);

    StmtLocMapping* new_mapping = new StmtLocMapping(GetLocationInfo(), this);

    // Optimistically just put it at the end.
    map.push_back(new_mapping);

    size_t curr_idx = map.size() - 1;
    if ( curr_idx == 0 )
        return true;

    // In case it wasn't actually lexically last, bubble it to the
    // right place.
    while ( map[curr_idx - 1]->StartsAfter(map[curr_idx]) ) {
        StmtLocMapping t = *map[curr_idx - 1];
        *map[curr_idx - 1] = *map[curr_idx];
        *map[curr_idx] = t;
        curr_idx--;
    }

    return true;
}

bool Stmt::IsPure() const { return false; }

void Stmt::Describe(ODesc* d) const {
    // The following is a handy add-on when doing AST debugging.
    // d->Add(util::fmt("%p: ", this));

    StmtDescribe(d);
}

void Stmt::StmtDescribe(ODesc* d) const {
    if ( ! d->IsReadable() || Tag() != STMT_EXPR )
        AddTag(d);
}

void Stmt::DecrBPCount() {
    if ( breakpoint_count )
        --breakpoint_count;
    else
        reporter->InternalError("breakpoint count decremented below 0");
}

void Stmt::AddTag(ODesc* d) const {
    if ( d->IsBinary() )
        d->Add(int(Tag()));
    else
        d->Add(stmt_name(Tag()));
    d->SP();
}

void Stmt::DescribeDone(ODesc* d) const {
    if ( d->IsReadable() && ! d->IsShort() )
        d->Add(";");
}

void Stmt::AccessStats(ODesc* d) const {
    if ( d->IncludeStats() ) {
        d->Add("(@");
        d->Add(last_access ? util::detail::fmt_access_time(last_access) : "<never>");
        d->Add(" #");
        d->Add(access_count);
        d->Add(")");
        d->NL();
    }
}

ExprListStmt::ExprListStmt(StmtTag t, ListExprPtr arg_l) : Stmt(t), l(std::move(arg_l)) {
    const ExprPList& e = l->Exprs();
    for ( const auto& expr : e ) {
        const auto& et = expr->GetType();
        if ( ! et || et->Tag() == TYPE_VOID )
            Error("value of type void illegal");
    }

    SetLocationInfo(l->GetLocationInfo());
}

ExprListStmt::~ExprListStmt() = default;

ValPtr ExprListStmt::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_NEXT;

    auto vals = eval_list(f, l.get());

    if ( vals )
        return DoExec(std::move(*vals), flow);

    return nullptr;
}

void ExprListStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d);
    l->Describe(d);
    DescribeDone(d);
}

TraversalCode ExprListStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    tc = l->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

static File* print_stdout = nullptr;

static EnumValPtr lookup_enum_val(const char* module_name, const char* name) {
    const auto& id = lookup_ID(name, module_name);
    assert(id);
    assert(id->IsEnumConst());

    EnumType* et = id->GetType()->AsEnumType();

    int index = et->Lookup(module_name, name);
    assert(index >= 0);

    return et->GetEnumVal(index);
}

static void print_log(const std::vector<ValPtr>& vals) {
    static auto plval = lookup_enum_val("Log", "PRINTLOG");
    static auto lpli = id::find_type<RecordType>("Log::PrintLogInfo");
    auto record = make_intrusive<RecordVal>(lpli);
    auto vec = make_intrusive<VectorVal>(id::string_vec);

    for ( const auto& val : vals ) {
        ODesc d(DESC_READABLE);
        val->Describe(&d);
        vec->Assign(vec->Size(), make_intrusive<StringVal>(d.Description()));
    }

    record->AssignTime(0, run_state::network_time);
    record->Assign(1, std::move(vec));
    log_mgr->Write(plval.get(), record.get());
}

ValPtr PrintStmt::DoExec(std::vector<ValPtr> vals, StmtFlowType& /* flow */) {
    do_print_stmt(vals);
    return nullptr;
}

void do_print_stmt(const std::vector<ValPtr>& vals) {
    if ( ! print_stdout )
        print_stdout = new File(stdout);

    File* f = print_stdout;
    int offset = 0;

    if ( vals.size() > 0 && vals[0] && vals[0]->GetType()->Tag() == TYPE_FILE ) {
        f = (vals)[0]->AsFile();
        if ( ! f->IsOpen() )
            return;

        ++offset;
    }

    static auto print_log_type = static_cast<BifEnum::Log::PrintLogType>(id::find_val("Log::print_to_log")->AsEnum());

    switch ( print_log_type ) {
        case BifEnum::Log::REDIRECT_NONE: break;
        case BifEnum::Log::REDIRECT_ALL: {
            print_log(vals);
            return;
        }
        case BifEnum::Log::REDIRECT_STDOUT:
            if ( f->FileHandle() == stdout ) {
                // Should catch even printing to a "manually opened" stdout file,
                // like "/dev/stdout" or "-".
                print_log(vals);
                return;
            }
            break;
        default: reporter->InternalError("unknown Log::PrintLogType value: %d", print_log_type); break;
    }

    DescStyle style = f->IsRawOutput() ? RAW_STYLE : STANDARD_STYLE;

    if ( f->IsRawOutput() ) {
        ODesc d(DESC_READABLE);
        d.SetFlush(false);
        d.SetStyle(style);

        describe_vals(vals, &d, offset);
        f->Write(d.Description(), d.Len());
    }
    else {
        ODesc d(DESC_READABLE, f);
        d.SetFlush(false);
        d.SetStyle(style);

        describe_vals(vals, &d, offset);
        f->Write("\n", 1);
    }
}

ExprStmt::ExprStmt(ExprPtr arg_e) : Stmt(STMT_EXPR), e(std::move(arg_e)) {
    if ( e && e->Tag() != EXPR_CALL && e->Tag() != EXPR_INLINE && e->IsPure() && e->GetType()->Tag() != TYPE_ERROR )
        Warn("expression value ignored");

    SetLocationInfo(e->GetLocationInfo());
}

ExprStmt::ExprStmt(StmtTag t, ExprPtr arg_e) : Stmt(t), e(std::move(arg_e)) {
    if ( e )
        SetLocationInfo(e->GetLocationInfo());
}

ExprStmt::~ExprStmt() = default;

ExprPtr ExprStmt::StmtExprPtr() const { return e; }

ValPtr ExprStmt::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_NEXT;

    auto v = e->Eval(f);

    if ( v )
        return DoExec(f, v.get(), flow);
    else
        return nullptr;
}

ValPtr ExprStmt::DoExec(Frame* /* f */, Val* /* v */, StmtFlowType& /* flow */) { return nullptr; }

bool ExprStmt::IsPure() const { return ! e || e->IsPure(); }

void ExprStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d);

    if ( d->IsReadable() && Tag() == STMT_IF )
        d->Add("(");

    if ( e )
        e->Describe(d);

    if ( Tag() == STMT_IF || Tag() == STMT_SWITCH ) {
        if ( d->IsReadable() ) {
            if ( Tag() == STMT_IF )
                d->Add(")");
            d->SP();
        }
    }
    else
        DescribeDone(d);
}

TraversalCode ExprStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    if ( e ) {
        tc = e->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

IfStmt::IfStmt(ExprPtr test, StmtPtr arg_s1, StmtPtr arg_s2)
    : ExprStmt(STMT_IF, std::move(test)), s1(std::move(arg_s1)), s2(std::move(arg_s2)) {
    if ( ! e->IsError() && ! IsBool(e->GetType()->Tag()) )
        e->Error("conditional in test must be boolean");

    const Location* loc1 = s1->GetLocationInfo();
    const Location* loc2 = s2->GetLocationInfo();
    SetLocationInfo(loc1, loc2);
}

IfStmt::~IfStmt() = default;

ValPtr IfStmt::DoExec(Frame* f, Val* v, StmtFlowType& flow) {
    // Treat 0 as false, but don't require 1 for true.
    Stmt* do_stmt = v->IsZero() ? s2.get() : s1.get();

    f->SetNextStmt(do_stmt);

    if ( ! pre_execute_stmt(do_stmt, f) ) { // ### Abort or something
    }

    auto result = do_stmt->Exec(f, flow);

    if ( ! post_execute_stmt(do_stmt, f, result.get(), &flow) ) { // ### Abort or something
    }

    return result;
}

bool IfStmt::IsPure() const { return e->IsPure() && s1->IsPure() && s2->IsPure(); }

void IfStmt::StmtDescribe(ODesc* d) const {
    ExprStmt::StmtDescribe(d);

    d->PushIndent();
    s1->AccessStats(d);
    s1->Describe(d);
    d->PopIndent();

    if ( d->IsReadable() ) {
        if ( s2->Tag() != STMT_NULL ) {
            d->Add("else");
            d->PushIndent();
            s2->AccessStats(d);
            s2->Describe(d);
            d->PopIndent();
        }
    }
    else
        s2->Describe(d);
}

TraversalCode IfStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    // Condition is stored in base class's "e" field.
    tc = e->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = TrueBranch()->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = FalseBranch()->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

static StmtTag get_last_stmt_tag(const Stmt* stmt) {
    if ( ! stmt )
        return STMT_NULL;

    if ( stmt->Tag() != STMT_LIST )
        return stmt->Tag();

    const StmtList* stmts = stmt->AsStmtList();
    auto len = stmts->Stmts().size();

    if ( len == 0 )
        return STMT_LIST;

    return get_last_stmt_tag(stmts->Stmts()[len - 1].get());
}

class FallthroughFinder : public TraversalCallback {
    TraversalCode PreStmt(const Stmt* stmt) override {
        if ( stmt->Tag() == STMT_SWITCH )
            // Don't search within nested switch-statements.
            return TC_ABORTSTMT;

        if ( stmt->Tag() != STMT_FALLTHROUGH )
            return TC_CONTINUE;

        reporter->PushLocation(stmt->GetLocationInfo());
        reporter->Error("invalid 'fallthrough' in type-casting 'case' block");
        reporter->PopLocation();
        return TC_CONTINUE;
    }
};

Case::Case(ListExprPtr arg_expr_cases, IDPList* arg_type_cases, StmtPtr arg_s)
    : expr_cases(std::move(arg_expr_cases)), type_cases(arg_type_cases), s(std::move(arg_s)) {
    StmtTag t = get_last_stmt_tag(Body());

    if ( t != STMT_BREAK && t != STMT_FALLTHROUGH && t != STMT_RETURN )
        Error("case block must end in break/fallthrough/return statement");

    if ( type_cases && Body() )
        for ( const auto& id : *type_cases )
            if ( id->Name() ) {
                FallthroughFinder ff;
                Body()->Traverse(&ff);
                break;
            }
}

Case::~Case() {
    if ( type_cases ) {
        for ( const auto& id : *type_cases )
            Unref(id);

        delete type_cases;
    }
}

void Case::Describe(ODesc* d) const {
    if ( ! (expr_cases || type_cases) ) {
        if ( ! d->IsBinary() )
            d->Add("default:");

        d->AddCount(0);

        d->PushIndent();
        Body()->AccessStats(d);
        Body()->Describe(d);
        d->PopIndent();

        return;
    }

    if ( ! d->IsBinary() )
        d->Add("case");

    if ( expr_cases ) {
        const ExprPList& e = expr_cases->Exprs();

        d->AddCount(e.length());

        loop_over_list(e, i) {
            if ( i > 0 && d->IsReadable() )
                d->Add(",");

            d->SP();
            e[i]->Describe(d);
        }
    }

    if ( type_cases ) {
        const IDPList& t = *type_cases;

        d->AddCount(t.length());

        loop_over_list(t, i) {
            if ( i > 0 && d->IsReadable() )
                d->Add(",");

            d->SP();
            d->Add("type");
            d->SP();
            t[i]->GetType()->Describe(d);

            if ( t[i]->Name() ) {
                d->SP();
                d->Add("as");
                d->SP();
                d->Add(t[i]->Name());
            }
        }
    }

    if ( d->IsReadable() )
        d->Add(":");

    d->PushIndent();
    Body()->AccessStats(d);
    Body()->Describe(d);
    d->PopIndent();
}

TraversalCode Case::Traverse(TraversalCallback* cb) const {
    TraversalCode tc;

    if ( expr_cases ) {
        tc = expr_cases->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( type_cases ) {
        // No traverse support for types.
    }

    tc = s->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    return TC_CONTINUE;
}

static void int_del_func(void* v) { delete (int*)v; }

void SwitchStmt::Init() {
    auto t = make_intrusive<TypeList>();
    t->Append(e->GetType());
    comp_hash = new CompositeHash(std::move(t));

    case_label_hash_map.SetDeleteFunc(int_del_func);
}

SwitchStmt::SwitchStmt(ExprPtr index, case_list* arg_cases)
    : ExprStmt(STMT_SWITCH, std::move(index)), cases(arg_cases) {
    Init();

    bool have_exprs = false;
    bool have_types = false;

    loop_over_list(*cases, i) {
        Case* c = (*cases)[i];
        ListExpr* le = c->ExprCases();
        IDPList* tl = c->TypeCases();

        if ( le ) {
            have_exprs = true;

            if ( ! is_atomic_type(e->GetType()) )
                e->Error("switch expression must be of an atomic type when cases are expressions");

            if ( ! le->GetType()->AsTypeList()->AllMatch(e->GetType(), false) ) {
                le->Error("case expression type differs from switch type", e.get());
                continue;
            }

            ExprPList& exprs = le->Exprs();

            loop_over_list(exprs, j) {
                if ( ! exprs[j]->IsConst() ) {
                    Expr* expr = exprs[j];

                    switch ( expr->Tag() ) {
                        // Simplify trivial unary plus/minus expressions on consts.
                        case EXPR_NEGATE: {
                            NegExpr* ne = (NegExpr*)(expr);

                            if ( ne->Op()->IsConst() )
                                Unref(exprs.replace(j, new ConstExpr(ne->Eval(nullptr))));
                        } break;

                        case EXPR_POSITIVE: {
                            PosExpr* pe = (PosExpr*)(expr);

                            if ( pe->Op()->IsConst() )
                                Unref(exprs.replace(j, new ConstExpr(pe->Eval(nullptr))));
                        } break;

                        case EXPR_NAME: {
                            NameExpr* ne = (NameExpr*)(expr);

                            if ( ne->Id()->IsConst() ) {
                                auto v = ne->Eval(nullptr);

                                if ( v )
                                    Unref(exprs.replace(j, new ConstExpr(std::move(v))));
                            }
                        } break;

                        default: break;
                    }
                }

                if ( ! exprs[j]->IsConst() )
                    exprs[j]->Error("case label expression isn't constant");
                else {
                    if ( ! AddCaseLabelValueMapping(exprs[j]->ExprVal(), i) )
                        exprs[j]->Error("duplicate case label");
                }
            }
        }

        else if ( tl ) {
            have_types = true;

            for ( const auto& t : *tl ) {
                const auto& ct = t->GetType();

                if ( ! can_cast_value_to_type(e->GetType().get(), ct.get()) ) {
                    c->Error("cannot cast switch expression to case type");
                    continue;
                }

                if ( ! AddCaseLabelTypeMapping(t, i) ) {
                    c->Error("duplicate case label");
                    continue;
                }
            }
        }

        else {
            if ( default_case_idx != -1 )
                c->Error("multiple default labels", (*cases)[default_case_idx]);
            else
                default_case_idx = i;
        }
    }

    if ( have_exprs && have_types )
        Error("cannot mix cases with expressions and types");
}

SwitchStmt::~SwitchStmt() {
    for ( const auto& c : *cases )
        Unref(c);

    delete cases;
    delete comp_hash;
}

bool SwitchStmt::AddCaseLabelValueMapping(const Val* v, int idx) {
    auto hk = comp_hash->MakeHashKey(*v, true);

    if ( ! hk ) {
        reporter->PushLocation(e->GetLocationInfo());
        reporter->InternalError("switch expression type mismatch (%s/%s)", type_name(v->GetType()->Tag()),
                                type_name(e->GetType()->Tag()));
    }

    int* label_idx = case_label_hash_map.Lookup(hk.get());

    if ( label_idx )
        return false;

    case_label_value_map[v] = idx;
    case_label_hash_map.Insert(hk.get(), new int{idx});
    return true;
}

bool SwitchStmt::AddCaseLabelTypeMapping(ID* t, int idx) {
    for ( const auto& i : case_label_type_list ) {
        if ( same_type(i.first->GetType(), t->GetType()) )
            return false;
    }

    auto e = std::make_pair(t, idx);
    case_label_type_list.push_back(e);

    return true;
}

std::pair<int, ID*> SwitchStmt::FindCaseLabelMatch(const Val* v) const {
    int label_idx = -1;
    ID* label_id = nullptr;

    // Find matching expression cases.
    if ( case_label_hash_map.Length() ) {
        auto hk = comp_hash->MakeHashKey(*v, true);

        if ( ! hk ) {
            reporter->PushLocation(e->GetLocationInfo());
            reporter->Error("switch expression type mismatch (%s/%s)", type_name(v->GetType()->Tag()),
                            type_name(e->GetType()->Tag()));
            return std::make_pair(-1, nullptr);
        }

        if ( auto i = case_label_hash_map.Lookup(hk.get()) )
            label_idx = *i;
    }

    // Find matching type cases.
    for ( const auto& i : case_label_type_list ) {
        auto id = i.first;
        const auto& type = id->GetType();

        if ( can_cast_value_to_type(v, type.get()) ) {
            label_idx = i.second;
            label_id = id;
            break;
        }
    }

    if ( label_idx < 0 )
        return std::make_pair(default_case_idx, nullptr);
    else
        return std::make_pair(label_idx, label_id);
}

ValPtr SwitchStmt::DoExec(Frame* f, Val* v, StmtFlowType& flow) {
    ValPtr rval;

    auto m = FindCaseLabelMatch(v);
    int matching_label_idx = m.first;
    ID* matching_id = m.second;

    if ( matching_label_idx == -1 )
        return nullptr;

    for ( int i = matching_label_idx; i < cases->length(); ++i ) {
        auto c = (*cases)[i];

        if ( matching_id ) {
            auto cv = cast_value_to_type(v, matching_id->GetType().get());
            f->SetElement(matching_id, std::move(cv));
        }

        flow = FLOW_NEXT;
        rval = c->Body()->Exec(f, flow);

        if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
            break;
    }

    if ( flow != FLOW_RETURN )
        flow = FLOW_NEXT;

    return rval;
}

bool SwitchStmt::IsPure() const {
    if ( ! e->IsPure() )
        return false;

    for ( const auto& c : *cases ) {
        if ( ! c->ExprCases()->IsPure() || ! c->Body()->IsPure() )
            return false;
    }

    return true;
}

void SwitchStmt::StmtDescribe(ODesc* d) const {
    ExprStmt::StmtDescribe(d);

    if ( ! d->IsBinary() )
        d->Add("{");

    d->PushIndent();
    d->AddCount(cases->length());
    for ( const auto& c : *cases )
        c->Describe(d);
    d->PopIndent();

    if ( ! d->IsBinary() )
        d->Add("}");
    d->NL();
}

TraversalCode SwitchStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    // Index is stored in base class's "e" field.
    tc = e->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    for ( const auto& c : *cases ) {
        tc = c->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

EventStmt::EventStmt(EventExprPtr arg_e) : ExprStmt(STMT_EVENT, arg_e), event_expr(std::move(arg_e)) {}

ValPtr EventStmt::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();

    auto args = eval_list(f, event_expr->Args());
    auto h = event_expr->Handler();

    if ( args && h ) {
        if ( event_trace_mgr )
            event_trace_mgr->ScriptEventQueued(h);

        event_mgr.Enqueue(h, std::move(*args));
    }

    flow = FLOW_NEXT;
    return nullptr;
}

TraversalCode EventStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    // Event is stored in base class's "e" field.
    tc = e->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

WhileStmt::WhileStmt(ExprPtr arg_loop_condition, StmtPtr arg_body)
    : Stmt(STMT_WHILE), loop_condition(std::move(arg_loop_condition)), body(std::move(arg_body)) {
    if ( ! loop_condition->IsError() && ! IsBool(loop_condition->GetType()->Tag()) )
        loop_condition->Error("while conditional must be boolean");
}

WhileStmt::~WhileStmt() = default;

bool WhileStmt::IsPure() const {
    if ( loop_condition->IsPure() && body->IsPure() )
        return ! loop_cond_pred_stmt || loop_cond_pred_stmt->IsPure();
    else
        return false;
}

void WhileStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d);

    if ( d->IsReadable() )
        d->Add("(");

    if ( loop_cond_pred_stmt ) {
        d->Add(" {");
        loop_cond_pred_stmt->Describe(d);
        d->Add("} ");
    }

    loop_condition->Describe(d);

    if ( d->IsReadable() )
        d->Add(")");

    d->SP();
    d->PushIndent();
    body->AccessStats(d);
    body->Describe(d);
    d->PopIndent();
}

TraversalCode WhileStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    if ( loop_cond_pred_stmt ) {
        tc = loop_cond_pred_stmt->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = loop_condition->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = body->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

ValPtr WhileStmt::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_NEXT;
    ValPtr rval;

    for ( ;; ) {
        if ( loop_cond_pred_stmt )
            loop_cond_pred_stmt->Exec(f, flow);

        auto cond = loop_condition->Eval(f);

        if ( ! cond )
            break;

        if ( ! cond->AsBool() )
            break;

        flow = FLOW_NEXT;
        rval = body->Exec(f, flow);

        if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
            break;
    }

    if ( flow == FLOW_LOOP || flow == FLOW_BREAK )
        flow = FLOW_NEXT;

    return rval;
}

ForStmt::ForStmt(IDPList* arg_loop_vars, ExprPtr loop_expr) : ExprStmt(STMT_FOR, std::move(loop_expr)) {
    loop_vars = arg_loop_vars;
    body = nullptr;

    if ( e->GetType()->Tag() == TYPE_TABLE ) {
        const auto& indices = e->GetType()->AsTableType()->GetIndexTypes();

        if ( loop_vars->length() == 1 && (*loop_vars)[0]->IsBlank() ) {
            // Special case support for looping with a single loop_var
            // ignoring the full index of a table.
            //
            //     for ( _, value )
            //         ...
            //
            return;
        }
        else if ( static_cast<int>(indices.size()) != loop_vars->length() ) {
            e->Error("wrong index size");
            return;
        }

        for ( auto i = 0u; i < indices.size(); i++ ) {
            const auto& ind_type = indices[i];
            const auto& lv = (*loop_vars)[i];
            const auto& lvt = lv->GetType();

            if ( lv->IsBlank() )
                continue;

            else if ( lvt ) {
                if ( ! same_type(lvt, ind_type) )
                    e->Error("type clash in iteration", lvt.get());
            }

            else {
                add_local({NewRef{}, lv}, ind_type, INIT_SKIP, nullptr, nullptr, VAR_REGULAR);
            }
        }
    }

    else if ( e->GetType()->Tag() == TYPE_VECTOR ) {
        if ( loop_vars->length() != 1 ) {
            e->Error("iterating over a vector requires only a single index type");
            return;
        }

        const auto& lv = (*loop_vars)[0];
        const auto& t = lv->GetType();

        if ( lv->IsBlank() ) {
            // nop
        }
        else if ( ! t )
            add_local({NewRef{}, lv}, base_type(TYPE_COUNT), INIT_SKIP, nullptr, nullptr, VAR_REGULAR);

        else if ( ! IsIntegral(t->Tag()) ) {
            e->Error("vector index in \"for\" loop must be integral");
            return;
        }
    }

    else if ( e->GetType()->Tag() == TYPE_STRING ) {
        if ( loop_vars->length() != 1 ) {
            e->Error("iterating over a string requires only a single index type");
            return;
        }

        const auto& lv = (*loop_vars)[0];
        const auto& t = lv->GetType();

        if ( lv->IsBlank() ) {
            // nop
        }
        else if ( ! t )
            add_local({NewRef{}, (*loop_vars)[0]}, base_type(TYPE_STRING), INIT_SKIP, nullptr, nullptr, VAR_REGULAR);

        else if ( t->Tag() != TYPE_STRING ) {
            e->Error("string index in \"for\" loop must be string");
            return;
        }
    }
    else
        e->Error("target to iterate over must be a table, set, vector, or string");
}

ForStmt::ForStmt(IDPList* arg_loop_vars, ExprPtr loop_expr, IDPtr val_var)
    : ForStmt(arg_loop_vars, std::move(loop_expr)) {
    value_var = std::move(val_var);

    auto t = e->GetType();
    zeek::TypePtr yield_type;

    if ( t->IsTable() )
        yield_type = t->AsTableType()->Yield();

    else if ( t->Tag() == TYPE_VECTOR )
        yield_type = t->AsVectorType()->Yield();

    else {
        e->Error("key value for loops only support iteration over tables or vectors");
        return;
    }

    // Verify value_vars type if it's already been defined
    if ( value_var->IsBlank() )
        value_var = ID::nil;

    else if ( value_var->GetType() ) {
        if ( ! same_type(value_var->GetType(), yield_type) )
            e->Error("type clash in iteration", value_var->GetType().get());
    }
    else
        add_local(value_var, yield_type, INIT_SKIP, nullptr, nullptr, VAR_REGULAR);
}

ForStmt::~ForStmt() {
    for ( const auto& var : *loop_vars )
        Unref(var);
    delete loop_vars;
}

ValPtr ForStmt::DoExec(Frame* f, Val* v, StmtFlowType& flow) {
    ValPtr ret;

    if ( v->GetType()->Tag() == TYPE_TABLE ) {
        TableVal* tv = v->AsTableVal();
        const PDict<TableEntryVal>* loop_vals = tv->AsTable();

        if ( ! loop_vals->Length() )
            return nullptr;

        // If there are only blank loop_vars (iterating over just the values),
        // we can avoid the RecreateIndex() overhead.
        bool all_loop_vars_blank = true;
        for ( const auto* lv : *loop_vars )
            all_loop_vars_blank &= lv->IsBlank();

        for ( const auto& lve : *loop_vals ) {
            auto k = lve.GetHashKey();
            auto* current_tev = lve.value;

            if ( value_var )
                f->SetElement(value_var, current_tev->GetVal());

            if ( ! all_loop_vars_blank ) {
                auto ind_lv = tv->RecreateIndex(*k);
                for ( int i = 0; i < ind_lv->Length(); i++ ) {
                    const auto* lv = (*loop_vars)[i];
                    if ( ! lv->IsBlank() )
                        f->SetElement(lv, ind_lv->Idx(i));
                }
            }

            flow = FLOW_NEXT;
            ret = body->Exec(f, flow);

            if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
                break;
        }
    }

    else if ( v->GetType()->Tag() == TYPE_VECTOR ) {
        VectorVal* vv = v->AsVectorVal();
        const auto& raw_vv = vv->RawVec();

        for ( auto i = 0u; i < vv->Size(); ++i ) {
            if ( ! raw_vv[i] )
                continue;

            // Set the loop variable to the current index, the value variable
            // to the current value, and make another pass over the loop body.
            if ( value_var )
                f->SetElement(value_var, vv->ValAt(i));

            const auto* lv = (*loop_vars)[0];
            if ( ! lv->IsBlank() )
                f->SetElement(lv, val_mgr->Count(i));

            flow = FLOW_NEXT;
            ret = body->Exec(f, flow);

            if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
                break;
        }
    }
    else if ( v->GetType()->Tag() == TYPE_STRING ) {
        StringVal* sval = v->AsStringVal();

        for ( int i = 0; i < sval->Len(); ++i ) {
            auto sv = make_intrusive<StringVal>(1, (const char*)sval->Bytes() + i);
            f->SetElement((*loop_vars)[0], std::move(sv));
            flow = FLOW_NEXT;
            ret = body->Exec(f, flow);

            if ( flow == FLOW_BREAK || flow == FLOW_RETURN )
                break;
        }
    }

    else
        e->Error("Invalid type in for-loop execution");

    if ( flow == FLOW_LOOP )
        flow = FLOW_NEXT; // last iteration exited with a "next"

    if ( flow == FLOW_BREAK )
        flow = FLOW_NEXT; // we've now finished the "break"

    return ret;
}

bool ForStmt::IsPure() const { return e->IsPure() && body->IsPure(); }

void ForStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d); // NOLINT(bugprone-parent-virtual-call)

    if ( d->IsReadable() )
        d->Add("(");

    if ( loop_vars->length() )
        d->Add("[");

    loop_over_list(*loop_vars, i) {
        (*loop_vars)[i]->Describe(d);
        if ( i > 0 )
            d->Add(",");
    }

    if ( loop_vars->length() )
        d->Add("]");

    if ( value_var ) {
        d->AddSP(",");
        value_var->Describe(d);
    }

    if ( d->IsReadable() )
        d->Add(" in ");

    e->Describe(d);

    if ( d->IsReadable() )
        d->Add(")");

    d->SP();

    d->PushIndent();
    body->AccessStats(d);
    body->Describe(d);
    d->PopIndent();
}

TraversalCode ForStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    for ( const auto& var : *loop_vars ) {
        tc = var->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    if ( value_var ) {
        tc = value_var->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = LoopExpr()->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = LoopBody()->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

ValPtr NextStmt::Exec(Frame* /* f */, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_LOOP;
    return nullptr;
}

bool NextStmt::IsPure() const { return true; }

void NextStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d);
    Stmt::DescribeDone(d);
}

TraversalCode NextStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

ValPtr BreakStmt::Exec(Frame* /* f */, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_BREAK;
    return nullptr;
}

bool BreakStmt::IsPure() const { return true; }

void BreakStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d);
    Stmt::DescribeDone(d);
}

TraversalCode BreakStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

ValPtr FallthroughStmt::Exec(Frame* /* f */, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_FALLTHROUGH;
    return nullptr;
}

bool FallthroughStmt::IsPure() const { return false; }

void FallthroughStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d);
    Stmt::DescribeDone(d);
}

TraversalCode FallthroughStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

ReturnStmt::ReturnStmt(ExprPtr arg_e) : ExprStmt(STMT_RETURN, std::move(arg_e)) {
    auto s = current_scope();

    if ( ! s || ! s->GetID() ) {
        Error("return statement outside of function/event");
        return;
    }

    FuncType* ft = s->GetID()->GetType()->AsFuncType();
    const auto& yt = ft->Yield();

    if ( s->GetID()->DoInferReturnType() ) {
        if ( e ) {
            ft->SetYieldType(e->GetType());
            s->GetID()->SetInferReturnType(false);
        }
    }

    else if ( ! yt || yt->Tag() == TYPE_VOID ) {
        if ( e )
            Error("return statement cannot have an expression");
    }

    else if ( ! e ) {
        if ( ft->Flavor() != FUNC_FLAVOR_HOOK && ! ft->ExpressionlessReturnOkay() )
            Error("return statement needs expression");
    }

    else {
        auto promoted_e = check_and_promote_expr(e, yt);

        if ( promoted_e )
            e = std::move(promoted_e);
    }
}

ValPtr ReturnStmt::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_RETURN;

    if ( e )
        return e->Eval(f);
    else
        return nullptr;
}

void ReturnStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d); // NOLINT(bugprone-parent-virtual-call)
    if ( ! d->IsReadable() )
        d->Add(e != nullptr);

    if ( e ) {
        if ( ! d->IsBinary() )
            d->Add("(");
        e->Describe(d);
        if ( ! d->IsBinary() )
            d->Add(")");
    }

    DescribeDone(d);
}

StmtList::StmtList() : Stmt(STMT_LIST) {}

ValPtr StmtList::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_NEXT;

    for ( const auto& stmt_ptr : stmts ) {
        auto stmt = stmt_ptr.get();

        f->SetNextStmt(stmt);

        if ( ! pre_execute_stmt(stmt, f) ) { // ### Abort or something
        }

        auto result = stmt->Exec(f, flow);

        if ( ! post_execute_stmt(stmt, f, result.get(), &flow) ) { // ### Abort or something
        }

        if ( flow != FLOW_NEXT || result || f->HasDelayed() )
            return result;
    }

    return nullptr;
}

bool StmtList::IsPure() const {
    for ( const auto& stmt : stmts )
        if ( ! stmt->IsPure() )
            return false;
    return true;
}

void StmtList::StmtDescribe(ODesc* d) const {
    if ( ! d->IsReadable() ) {
        AddTag(d);
        d->AddCount(stmts.size());
    }

    if ( stmts.empty() )
        DescribeDone(d);

    else {
        if ( ! d->IsBinary() ) {
            d->Add("{ ");
            d->NL();
        }

        for ( const auto& stmt : stmts ) {
            stmt->Describe(d);
            d->NL();
        }

        if ( ! d->IsBinary() )
            d->Add("}");
    }
}

TraversalCode StmtList::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    for ( const auto& stmt : stmts ) {
        tc = stmt->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

InitStmt::InitStmt(std::vector<IDPtr> arg_inits) : Stmt(STMT_INIT) {
    inits = std::move(arg_inits);

    if ( ! inits.empty() )
        SetLocationInfo(inits[0]->GetLocationInfo());
}

ValPtr InitStmt::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_NEXT;

    for ( const auto& aggr : inits ) {
        const auto& t = aggr->GetType();

        ValPtr v;

        switch ( t->Tag() ) {
            case TYPE_RECORD: v = make_intrusive<RecordVal>(cast_intrusive<RecordType>(t)); break;
            case TYPE_VECTOR: v = make_intrusive<VectorVal>(cast_intrusive<VectorType>(t)); break;
            case TYPE_TABLE: v = make_intrusive<TableVal>(cast_intrusive<TableType>(t), aggr->GetAttrs()); break;
            default: break;
        }

        f->SetElement(aggr, std::move(v));
    }

    return nullptr;
}

void InitStmt::StmtDescribe(ODesc* d) const {
    AddTag(d);

    if ( ! d->IsReadable() )
        d->AddCount(inits.size());

    for ( size_t i = 0; i < inits.size(); ++i ) {
        if ( ! d->IsBinary() && i > 0 )
            d->AddSP(",");

        inits[i]->Describe(d);
    }

    DescribeDone(d);
}

TraversalCode InitStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    for ( const auto& init : inits ) {
        tc = init->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

NullStmt::NullStmt(bool arg_is_directive) : Stmt(STMT_NULL), is_directive(arg_is_directive) {}

ValPtr NullStmt::Exec(Frame* /* f */, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_NEXT;
    return nullptr;
}

bool NullStmt::IsPure() const { return true; }

void NullStmt::StmtDescribe(ODesc* d) const {
    if ( d->IsReadable() )
        DescribeDone(d);
    else
        AddTag(d);
}

TraversalCode NullStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

AssertStmt::AssertStmt(ExprPtr cond, ExprPtr arg_msg)
    : ExprStmt(STMT_ASSERT, std::move(cond)), msg(std::move(arg_msg)) {
    if ( ! IsBool(e->GetType()->Tag()) )
        e->Error("conditional must be boolean");

    if ( msg && ! IsString(msg->GetType()->Tag()) )
        msg->Error("message must be string");

    zeek::ODesc desc;
    desc.SetShort(true);
    desc.SetQuotes(true);
    e->Describe(&desc);

    cond_desc = desc.Description();
}

ValPtr AssertStmt::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_NEXT;

    static auto assertion_result_hook = id::find_func("assertion_result");
    bool run_result_hook = assertion_result_hook && assertion_result_hook->HasEnabledBodies();
    auto assert_result = e->Eval(f)->AsBool();

    if ( ! assert_result || run_result_hook ) {
        zeek::StringValPtr msg_val = zeek::val_mgr->EmptyString();

        if ( msg )
            // It's up to the script writing to assure that the expression
            // works regardless of the state of the condition. If they
            // fail to do so, they can get an exception at this point.
            msg_val = cast_intrusive<zeek::StringVal>(msg->Eval(f));

        report_assert(assert_result, cond_desc, msg_val, GetLocationInfo());
    }

    return Val::nil;
}

void AssertStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d); // NOLINT(bugprone-parent-virtual-call)

    // Quoting strings looks better when describing assert
    // statements. So turn it on explicitly.
    //
    // E.g., md5_hash("") ends up as md5_hash() without quoting.
    auto orig_quotes = d->WantQuotes();
    d->SetQuotes(true);

    e->Describe(d);

    if ( msg_setup_stmt ) {
        d->Add("{ ");
        msg_setup_stmt->Describe(d);
        d->Add(" }");
    }

    if ( msg ) {
        d->Add(",");
        d->SP();
        msg->Describe(d);
    }

    DescribeDone(d);

    d->SetQuotes(orig_quotes);
}

TraversalCode AssertStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    tc = e->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);
    if ( msg ) {
        if ( msg_setup_stmt ) {
            tc = msg_setup_stmt->Traverse(cb);
            HANDLE_TC_STMT_PRE(tc);
        }

        tc = msg->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

class AssertException : public InterpreterException {
public:
    AssertException() {}
};

void report_assert(bool cond, std::string_view cond_desc, StringValPtr msg_val, const Location* loc) {
    static auto assertion_failure_hook = id::find_func("assertion_failure");
    static auto assertion_result_hook = id::find_func("assertion_result");

    bool run_result_hook = assertion_result_hook && assertion_result_hook->HasEnabledBodies();
    bool run_failure_hook = assertion_failure_hook && assertion_failure_hook->HasEnabledBodies();

    auto cond_val = zeek::make_intrusive<zeek::StringVal>(cond_desc);

    VectorValPtr bt = nullptr;
    if ( run_result_hook || run_failure_hook ) {
        bt = get_current_script_backtrace();
        auto assert_elem = make_backtrace_element("assert", MakeEmptyCallArgumentVector(), loc);
        bt->Insert(0, std::move(assert_elem));
    }

    // Breaking from either the assertion_failure() or assertion_result()
    // hook can be used to suppress the default log message.
    bool report_error = true;

    if ( run_result_hook )
        report_error &= assertion_result_hook->Invoke(zeek::val_mgr->Bool(cond), cond_val, msg_val, bt)->AsBool();

    if ( cond )
        return;

    if ( run_failure_hook )
        report_error &= assertion_failure_hook->Invoke(cond_val, msg_val, bt)->AsBool();

    if ( report_error ) {
        std::string reporter_msg = util::fmt("assertion failure: %s", cond_val->CheckString());
        if ( msg_val->Len() > 0 )
            reporter_msg += util::fmt(" (%s)", msg_val->CheckString());

        reporter->PushLocation(loc);
        reporter->Error("%s", reporter_msg.c_str());
        reporter->PopLocation();
    }

    throw AssertException();
}

WhenInfo::WhenInfo(ExprPtr arg_cond, FuncType::CaptureList* arg_cl, bool arg_is_return)
    : cond(std::move(arg_cond)), cl(arg_cl), is_return(arg_is_return) {
    if ( ! cl )
        cl = new zeek::FuncType::CaptureList;

    BuildProfile();

    // Create the internal lambda we'll use to manage the captures.
    static int num_params = 0; // to ensure each is distinct
    lambda_param_id = util::fmt("when-param-%d", ++num_params);

    auto param_list = new type_decl_list();
    auto count_t = base_type(TYPE_COUNT);
    param_list->push_back(new TypeDecl(util::copy_string(lambda_param_id.c_str(), lambda_param_id.size()), count_t));
    auto params = make_intrusive<RecordType>(param_list);

    lambda_ft = make_intrusive<FuncType>(params, base_type(TYPE_ANY), FUNC_FLAVOR_FUNCTION);

    if ( ! is_return )
        lambda_ft->SetExpressionlessReturnOkay(true);

    lambda_ft->SetCaptures(*cl);

    auto id = current_scope()->GenerateTemporary("when-internal");
    id->SetType(lambda_ft);
    push_scope(std::move(id), nullptr);

    param_id = install_ID(lambda_param_id.c_str(), current_module.c_str(), false, false);
    param_id->SetType(count_t);
}

WhenInfo::WhenInfo(const WhenInfo* orig) {
    if ( orig->cl ) {
        cl = new FuncType::CaptureList;
        *cl = *orig->cl;
    }

    cond = orig->OrigCond()->Duplicate();

    // We don't duplicate these, as they'll be compiled separately.
    s = orig->OrigBody();
    timeout_s = orig->OrigBody();

    timeout = orig->OrigTimeout();
    if ( timeout )
        timeout = timeout->Duplicate();

    lambda = cast_intrusive<LambdaExpr>(orig->Lambda()->Duplicate());

    is_return = orig->IsReturn();

    BuildProfile();
}

WhenInfo::WhenInfo(bool arg_is_return) : is_return(arg_is_return) {
    cl = new zeek::FuncType::CaptureList;
    BuildInvokeElems();
}

void WhenInfo::BuildProfile() {
    ProfileFunc cond_pf(cond.get());

    auto when_expr_locals_set = cond_pf.Locals();
    when_expr_globals = cond_pf.AllGlobals();
    when_new_locals = cond_pf.WhenLocals();

    // Make any when-locals part of our captures, if not already present,
    // to enable sharing between the condition and the body/timeout code.
    for ( auto& wl : when_new_locals ) {
        bool is_present = false;

        for ( auto& c : *cl )
            if ( c.Id() == wl ) {
                is_present = true;
                break;
            }

        if ( ! is_present ) {
            IDPtr wl_ptr = {NewRef{}, const_cast<ID*>(wl)};
            cl->emplace_back(std::move(wl_ptr), false);
        }

        // In addition, don't treat them as external locals that
        // existed at the onset.
        when_expr_locals_set.erase(wl);
    }

    for ( auto& w : when_expr_locals_set ) {
        // We need IDPtr versions of the locals so we can manipulate
        // them during script optimization.
        auto non_const_w = const_cast<ID*>(w);
        when_expr_locals.emplace_back(NewRef{}, non_const_w);
    }
}

void WhenInfo::Build(StmtPtr ws) {
    // Our general strategy is to construct a single lambda (so that
    // the values of captures are shared across all of its elements)
    // that's used for all three of the "when" components: condition,
    // body, and timeout body.  The idea is that the lambda is passed
    // a single argument that specifies the particular functionality
    // to execute (1 = condition, 2 = body, 3 = timeout).  It gets tricky
    // in that the condition needs to return a boolean, whereas the body
    // and timeout *might* return a value (for "return when") constructs,
    // or might not (for vanilla "when").  We address that issue by
    // (1) making the return type be "any", and (2) introducing elsewhere
    // the notion of functions marked as being allowed to have bare
    // returns (no associated expression) even though they have a return
    // type (to deal with the vanilla "when" case).

    // Build the AST elements of the lambda.

    // First, the constants we'll need.
    BuildInvokeElems();

    if ( lambda )
        // No need to build the lambda.
        return;

    auto true_const = make_intrusive<ConstExpr>(val_mgr->True());

    // Access to the parameter that selects which action we're doing.
    ASSERT(param_id);
    auto param = make_intrusive<NameExpr>(param_id);

    // Expressions for testing for the latter constants.
    auto one_test = make_intrusive<EqExpr>(EXPR_EQ, param, one_const);
    auto two_test = make_intrusive<EqExpr>(EXPR_EQ, param, two_const);

    auto empty = make_intrusive<NullStmt>();

    auto test_cond = make_intrusive<ReturnStmt>(cond);
    auto do_test = make_intrusive<IfStmt>(one_test, test_cond, empty);

    auto else_branch = timeout_s ? timeout_s : empty;

    auto do_bodies = make_intrusive<IfStmt>(two_test, s, else_branch);
    auto any_true_const = make_intrusive<CoerceToAnyExpr>(true_const);
    auto dummy_return = make_intrusive<ReturnStmt>(any_true_const);

    auto shebang = make_intrusive<StmtList>(do_test, do_bodies, dummy_return);

    auto ingredients = std::make_shared<FunctionIngredients>(current_scope(), shebang, current_module);
    auto outer_ids = gather_outer_ids(pop_scope(), ingredients->Body());

    lambda = make_intrusive<LambdaExpr>(std::move(ingredients), std::move(outer_ids), "", ws);
    lambda->SetPrivateCaptures(when_new_locals);

    auto cl = cond->GetLocationInfo();

    for ( const auto& e : std::vector<ExprPtr>{true_const, param, one_test, two_test, lambda} )
        e->SetLocationInfo(cl);

    for ( const auto& s :
          std::vector<StmtPtr>{empty, test_cond, do_test, else_branch, do_bodies, dummy_return, shebang} )
        s->SetLocationInfo(cl);

    analyze_when_lambda(lambda.get());
}

void WhenInfo::Instantiate(Frame* f) { Instantiate(lambda->Eval(f)); }

void WhenInfo::Instantiate(ValPtr func) {
    curr_lambda = make_intrusive<ConstExpr>(std::move(func));
    if ( cond )
        curr_lambda->SetLocationInfo(cond->GetLocationInfo());
}

ExprPtr WhenInfo::Cond() {
    if ( cond )
        return with_location_of(make_intrusive<CallExpr>(curr_lambda, invoke_cond), cond);
    else
        return make_intrusive<CallExpr>(curr_lambda, invoke_cond);
}

StmtPtr WhenInfo::WhenBody() {
    auto invoke = make_intrusive<CallExpr>(curr_lambda, invoke_s);
    if ( s )
        invoke->SetLocationInfo(s->GetLocationInfo());
    return make_intrusive<ReturnStmt>(invoke, true);
}

double WhenInfo::TimeoutVal(Frame* f) {
    if ( timeout ) {
        auto t = timeout->Eval(f);
        if ( t )
            return t->AsDouble();
    }

    return -1.0; // signals "no timeout"
}

StmtPtr WhenInfo::TimeoutStmt() {
    auto invoke = make_intrusive<CallExpr>(curr_lambda, invoke_timeout);
    if ( timeout_s )
        invoke->SetLocationInfo(timeout_s->GetLocationInfo());
    return make_intrusive<ReturnStmt>(invoke, true);
}

void WhenInfo::BuildInvokeElems() {
    one_const = make_intrusive<ConstExpr>(val_mgr->Count(1));
    two_const = make_intrusive<ConstExpr>(val_mgr->Count(2));
    three_const = make_intrusive<ConstExpr>(val_mgr->Count(3));

    invoke_cond = make_intrusive<ListExpr>(one_const);
    invoke_s = make_intrusive<ListExpr>(two_const);
    invoke_timeout = make_intrusive<ListExpr>(three_const);

    if ( cond ) {
        // "cond" might not exist if we're constructing via -O gen-C++.
        auto cl = cond->GetLocationInfo();

        for ( const auto& e :
              std::vector<ExprPtr>{one_const, two_const, three_const, invoke_cond, invoke_s, invoke_timeout} )
            e->SetLocationInfo(cl);
    }
}

WhenStmt::WhenStmt(std::shared_ptr<WhenInfo> arg_wi) : Stmt(STMT_WHEN), wi(std::move(arg_wi)) {
    wi->Build(ThisPtr());

    auto cond = wi->OrigCond();

    if ( ! cond->IsError() && ! IsBool(cond->GetType()->Tag()) )
        cond->Error("conditional in test must be boolean");

    auto te = wi->OrigTimeout();

    if ( te ) {
        if ( te->IsError() )
            return;

        TypeTag bt = te->GetType()->Tag();
        if ( bt != TYPE_TIME && bt != TYPE_INTERVAL )
            te->Error("when timeout requires a time or time interval");
    }
}

ValPtr WhenStmt::Exec(Frame* f, StmtFlowType& flow) {
    RegisterAccess();
    flow = FLOW_NEXT;

    wi->Instantiate(f);

    auto timeout = wi->TimeoutVal(f);

    std::vector<ValPtr> local_aggrs;
    for ( auto& l : wi->WhenExprLocals() ) {
        auto v = f->GetElementByID(l);
        if ( v && v->Modifiable() )
            local_aggrs.emplace_back(std::move(v));
    }

    (void)make_intrusive<trigger::Trigger>(wi, wi->WhenExprGlobals(), local_aggrs, timeout, f, location);

    return nullptr;
}

bool WhenStmt::IsPure() const { return false; }

void WhenStmt::StmtDescribe(ODesc* d) const {
    Stmt::StmtDescribe(d);

    auto cl = wi->Captures();
    if ( d->IsReadable() && ! cl->empty() ) {
        d->Add("[");
        for ( auto& c : *cl ) {
            if ( &c != &(*cl)[0] )
                d->AddSP(",");

            if ( c.IsDeepCopy() )
                d->Add("copy ");

            if ( c.Id() )
                d->Add(c.Id()->Name());
            else
                d->Add("<error>");
        }
        d->Add("]");
    }

    if ( d->IsReadable() )
        d->Add("(");

    wi->OrigCond()->Describe(d);

    if ( d->IsReadable() )
        d->Add(")");

    d->SP();
    d->PushIndent();
    wi->OrigBody()->AccessStats(d);
    wi->OrigBody()->Describe(d);
    d->PopIndent();

    if ( wi->OrigTimeout() ) {
        if ( d->IsReadable() ) {
            d->SP();
            d->Add("timeout");
            d->SP();
            wi->OrigTimeout()->Describe(d);
            d->SP();
            d->PushIndent();
            wi->OrigTimeoutStmt()->AccessStats(d);
            wi->OrigTimeoutStmt()->Describe(d);
            d->PopIndent();
        }
        else {
            wi->OrigTimeout()->Describe(d);
            wi->OrigTimeoutStmt()->Describe(d);
        }
    }
}

TraversalCode WhenStmt::Traverse(TraversalCallback* cb) const {
    TraversalCode tc = cb->PreStmt(this);
    HANDLE_TC_STMT_PRE(tc);

    tc = wi->Lambda()->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    auto e = wi->TimeoutExpr();
    if ( e ) {
        tc = e->Traverse(cb);
        HANDLE_TC_STMT_PRE(tc);
    }

    tc = cb->PostStmt(this);
    HANDLE_TC_STMT_POST(tc);
}

ValPtr StdFunctionStmt::Exec(Frame* f, StmtFlowType& flow) {
    zeek::Args args = *f->GetFuncArgs();

    // Set this to NEXT by default. The function can override that if it wants.
    flow = FLOW_NEXT;
    func(args, flow);

    return nullptr;
}

} // namespace zeek::detail
