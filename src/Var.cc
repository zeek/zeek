// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Var.h"

#include <memory>

#include "zeek/Desc.h"
#include "zeek/EventRegistry.h"
#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/ScriptCoverageManager.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"
#include "zeek/Val.h"
#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/StmtOptInfo.h"
#include "zeek/script_opt/UsageAnalyzer.h"

namespace zeek::detail {

static bool add_prototype(const IDPtr& id, Type* t, std::vector<AttrPtr>* attrs) {
    if ( ! IsFunc(id->GetType()->Tag()) )
        return false;

    if ( ! IsFunc(t->Tag()) ) {
        t->Error("type incompatible with previous definition", id.get());
        return false;
    }

    auto canon_ft = id->GetType()->AsFuncType();
    auto alt_ft = t->AsFuncType();

    if ( canon_ft->Flavor() != alt_ft->Flavor() ) {
        alt_ft->Error("incompatible function flavor", canon_ft);
        return false;
    }

    if ( canon_ft->Flavor() == FUNC_FLAVOR_FUNCTION ) {
        alt_ft->Error("redeclaration of function", canon_ft);
        return false;
    }

    const auto& canon_args = canon_ft->Params();
    const auto& alt_args = alt_ft->Params();

    if ( auto p = canon_ft->FindPrototype(*alt_args); p ) {
        alt_ft->Error("alternate function prototype already exists", p->args.get(), true);
        return false;
    }

    std::map<int, int> offsets;

    for ( auto i = 0; i < alt_args->NumFields(); ++i ) {
        auto field = alt_args->FieldName(i);

        if ( alt_args->FieldDecl(i)->attrs ) {
            alt_ft->Error(util::fmt("alternate function prototype arguments may not have attributes: arg '%s'", field),
                          canon_ft);
            return false;
        }

        auto o = canon_args->FieldOffset(field);

        if ( o < 0 ) {
            alt_ft->Error(util::fmt("alternate function prototype arg '%s' not found in canonical prototype", field),
                          canon_ft);
            return false;
        }

        offsets[o] = i;
    }

    auto deprecated = false;
    std::string depr_msg;

    if ( attrs )
        for ( const auto& a : *attrs )
            if ( a->Tag() == ATTR_DEPRECATED ) {
                deprecated = true;
                depr_msg = a->DeprecationMessage();
                break;
            }

    FuncType::Prototype p;
    p.deprecated = deprecated;
    p.deprecation_msg = std::move(depr_msg);
    p.args = alt_args;
    p.offsets = std::move(offsets);

    canon_ft->AddPrototype(std::move(p));
    return true;
}

static ExprPtr initialize_var(const IDPtr& id, InitClass c, ExprPtr init) {
    if ( ! id->HasVal() ) {
        if ( c == INIT_REMOVE )
            return nullptr;

        bool no_init = ! init;

        if ( ! no_init && init->Tag() == EXPR_LIST )
            no_init = init->AsListExpr()->Exprs().empty();

        if ( no_init ) {
            auto& t = id->GetType();

            if ( ! IsAggr(t) )
                return nullptr;

            ValPtr init_val;

            if ( t->Tag() == TYPE_RECORD ) {
                try {
                    init_val = make_intrusive<RecordVal>(cast_intrusive<RecordType>(t));
                } catch ( InterpreterException& ) {
                    id->Error("initialization failed");
                    return nullptr;
                }
            }

            else if ( t->Tag() == TYPE_TABLE )
                init_val = make_intrusive<TableVal>(cast_intrusive<TableType>(t), id->GetAttrs());

            else if ( t->Tag() == TYPE_VECTOR )
                init_val = make_intrusive<VectorVal>(cast_intrusive<VectorType>(t));

            init = make_intrusive<ConstExpr>(init_val);
            c = INIT_FULL;
        }

        else if ( c == INIT_EXTRA )
            c = INIT_FULL;
    }

    bool is_const = id->IsConst() || id->IsOption();
    auto lhs = make_intrusive<NameExpr>(id, is_const);
    ExprPtr assignment;

    if ( c == INIT_FULL )
        assignment = make_intrusive<AssignExpr>(lhs, init, false);
    else if ( c == INIT_EXTRA )
        assignment = make_intrusive<AddToExpr>(lhs, init);
    else if ( c == INIT_REMOVE )
        assignment = make_intrusive<RemoveFromExpr>(lhs, init);
    else
        // This can happen due to error propagation.
        return nullptr;

    if ( assignment->IsError() )
        return nullptr;

    return assignment;
}

static void make_var(const IDPtr& id, TypePtr t, InitClass c, ExprPtr init, std::unique_ptr<std::vector<AttrPtr>> attr,
                     DeclType dt, bool do_init) {
    if ( c == INIT_NONE && init ) {
        // This can happen because the grammar allows any "init_class",
        // including none, to be followed by an expression.
        init->Error("Initialization not preceded by =/+=/-= is not allowed.");
    }

    if ( init && init->Tag() == EXPR_LIST ) {
        auto& init_t = t ? t : id->GetType();
        init = expand_op(cast_intrusive<ListExpr>(init), init_t);
    }

    if ( id->GetType() && ! id->IsBlank() ) {
        if ( id->IsRedefinable() || (! init && attr && ! IsFunc(id->GetType()->Tag())) ) {
            Obj* redef_obj = init ? (Obj*)init.get() : (Obj*)t.get();
            if ( dt != VAR_REDEF )
                id->Warn("redefinition requires \"redef\"", redef_obj, true);
        }

        else if ( dt == VAR_REDEF && ! id->IsRedefinable() ) {
            id->Error("cannot redefine a variable not marked with &redef", init.get());
            return;
        }

        else if ( dt != VAR_REDEF || init || ! attr ) {
            if ( IsFunc(id->GetType()->Tag()) && ! init )
                add_prototype(id, t.get(), attr.get());
            else
                id->Error("already defined", init.get());

            return;
        }
    }

    if ( dt == VAR_REDEF ) {
        if ( ! id->GetType() ) {
            id->Error("\"redef\" used but not previously defined");
            return;
        }

        if ( ! t )
            t = id->GetType();
    }

    if ( id->GetType() && id->GetType()->Tag() != TYPE_ERROR && ! id->IsBlank() ) {
        if ( dt != VAR_REDEF && (! init || ! do_init || (! t && ! (t = init_type(init)))) ) {
            id->Error("already defined", init.get());
            return;
        }

        // Allow redeclaration in order to initialize.
        if ( ! same_type(t, id->GetType()) ) {
            id->Error("redefinition changes type", init.get());
            return;
        }
    }

    if ( t && t->IsSet() ) { // Check for set with explicit elements.
        SetType* st = t->AsTableType()->AsSetType();
        const auto& elements = st->Elements();

        if ( elements ) {
            if ( init ) {
                id->Error("double initialization", init.get());
                return;
            }

            init = elements;
        }
    }

    if ( ! t ) { // Take type from initialization.
        if ( ! init ) {
            id->Error("no type given");
            return;
        }

        t = init_type(init);
        if ( ! t ) {
            id->SetType(error_type());
            return;
        }
    }

    id->SetType(t);

    if ( attr )
        id->AddAttrs(make_intrusive<Attributes>(std::move(*attr), t, false, id->IsGlobal()), dt == VAR_REDEF);

    if ( init ) {
        switch ( init->Tag() ) {
            case EXPR_TABLE_CONSTRUCTOR: {
                auto* ctor = static_cast<TableConstructorExpr*>(init.get());
                if ( ctor->GetAttrs() )
                    id->AddAttrs(ctor->GetAttrs());
                else
                    ctor->SetAttrs(id->GetAttrs());
            } break;

            case EXPR_SET_CONSTRUCTOR: {
                auto* ctor = static_cast<SetConstructorExpr*>(init.get());
                if ( ctor->GetAttrs() )
                    id->AddAttrs(ctor->GetAttrs());
                else
                    ctor->SetAttrs(id->GetAttrs());
            } break;

            default: break;
        }
    }

    if ( do_init ) {
        if ( c == INIT_NONE && dt == VAR_REDEF && t->IsTable() && init && init->Tag() == EXPR_ASSIGN )
            // e.g. 'redef foo["x"] = 1' is missing an init class, but the
            // intention clearly isn't to overwrite entire existing table val.
            c = INIT_EXTRA;

        if ( init &&
             ((c == INIT_EXTRA && id->GetAttr(ATTR_ADD_FUNC)) || (c == INIT_REMOVE && id->GetAttr(ATTR_DEL_FUNC))) ) {
            // Just apply the function.
            id->SetVal(init, c);
            id->GetOptInfo()->AddInitExpr(init, c);
        }

        else if ( dt != VAR_REDEF || init || ! attr ) {
            auto init_expr = initialize_var(id, c, init);
            if ( init_expr ) {
                id->GetOptInfo()->AddInitExpr(init_expr);

                try {
                    (void)init_expr->Eval(nullptr);
                } catch ( InterpreterException& ) {
                    id->Error("initialization failed");
                }
            }
        }
    }

    if ( dt == VAR_CONST ) {
        if ( ! init && ! id->IsRedefinable() )
            id->Error("const variable must be initialized");

        id->SetConst();
    }

    if ( dt == VAR_OPTION ) {
        if ( ! init && ! IsContainer(t->Tag()) )
            id->Error("option variable must be initialized");

        id->SetOption();
    }

    id->UpdateValAttrs();

    if ( t && t->Tag() == TYPE_FUNC &&
         (t->AsFuncType()->Flavor() == FUNC_FLAVOR_EVENT || t->AsFuncType()->Flavor() == FUNC_FLAVOR_HOOK) ) {
        // For events, add a function value (without any body) here so that
        // we can later access the ID even if no implementations have been
        // defined.
        auto f = make_intrusive<ScriptFunc>(id);
        id->SetVal(make_intrusive<FuncVal>(std::move(f)));
    }
}

void add_global(const IDPtr& id, TypePtr t, InitClass c, ExprPtr init, std::unique_ptr<std::vector<AttrPtr>> attr,
                DeclType dt) {
    make_var(id, std::move(t), c, std::move(init), std::move(attr), dt, true);
}

StmtPtr add_local(IDPtr id, TypePtr t, InitClass c, ExprPtr init, std::unique_ptr<std::vector<AttrPtr>> attr,
                  DeclType dt) {
    make_var(id, std::move(t), c, init, std::move(attr), dt, false);

    if ( init ) {
        if ( c != INIT_FULL )
            id->Error("can't use += / -= for initializations of local variables");

        // copy Location to the stack, because AssignExpr may free "init"
        const Location location = init->GetLocationInfo() ? *init->GetLocationInfo() : no_location;

        auto name_expr = make_intrusive<NameExpr>(id, dt == VAR_CONST);
        auto assign_expr =
            make_intrusive<AssignExpr>(std::move(name_expr), std::move(init), 0, nullptr, id->GetAttrs());
        auto stmt = make_intrusive<ExprStmt>(std::move(assign_expr));
        stmt->SetLocationInfo(&location);
        return stmt;
    }

    else {
        if ( c != INIT_SKIP )
            current_scope()->AddInit(std::move(id));

        return make_intrusive<NullStmt>();
    }
}

extern ExprPtr add_and_assign_local(IDPtr id, ExprPtr init, ValPtr val) {
    make_var(id, nullptr, INIT_FULL, init, nullptr, VAR_REGULAR, false);
    auto name_expr = make_intrusive<NameExpr>(std::move(id));
    return make_intrusive<AssignExpr>(std::move(name_expr), std::move(init), false, std::move(val));
}

void add_type(ID* id, TypePtr t, std::unique_ptr<std::vector<AttrPtr>> attr) {
    std::string new_type_name = id->Name();
    std::string old_type_name = t->GetName();

    TypePtr tnew;

    if ( (t->Tag() == TYPE_RECORD || t->Tag() == TYPE_ENUM) &&
         (old_type_name.empty() || old_type_name == new_type_name) ) {
        // An extensible type (record/enum) being declared for first time.
        //
        // Enum types are initialized with the same name as their identifier
        // when declared for the first time, double check that here.
        if ( t->Tag() == TYPE_ENUM && new_type_name != old_type_name )
            reporter->InternalError("enum type has unexpected names: '%s' and '%s'", old_type_name.c_str(),
                                    new_type_name.c_str());

        tnew = std::move(t);
    }
    else {
        // If the old type is an error or the old type doesn't exist, then return
        // an error instead of trying to clone it.
        if ( t->Tag() == TYPE_ERROR && t->InternalType() == TYPE_INTERNAL_ERROR ) {
            reporter->Error("Error trying to create alias to nonexistent type");
            return;
        }

        // Clone the type to preserve type name aliasing.
        tnew = t->ShallowClone();
    }

    Type::RegisterAlias(new_type_name, tnew);

    if ( new_type_name != old_type_name && ! old_type_name.empty() )
        Type::RegisterAlias(old_type_name, tnew);

    tnew->SetName(id->Name());

    id->SetType(tnew);
    id->MakeType();

    if ( attr )
        id->SetAttrs(make_intrusive<Attributes>(std::move(*attr), tnew, false, false));
}

static std::set<std::string> all_module_names;

void add_module(const char* module_name) {
    all_module_names.emplace(module_name);
    switch_to_module(module_name);
}

const std::set<std::string>& module_names() { return all_module_names; }

static void transfer_arg_defaults(RecordType* args, RecordType* recv) {
    for ( int i = 0; i < args->NumFields(); ++i ) {
        TypeDecl* args_i = args->FieldDecl(i);
        TypeDecl* recv_i = recv->FieldDecl(i);

        const auto& def = args_i->attrs ? args_i->attrs->Find(ATTR_DEFAULT) : nullptr;

        if ( ! def )
            continue;

        if ( ! recv_i->attrs ) {
            std::vector<AttrPtr> a{def};
            recv_i->attrs = make_intrusive<Attributes>(std::move(a), recv_i->type, true, false);
        }

        else if ( ! recv_i->attrs->Find(ATTR_DEFAULT) )
            recv_i->attrs->AddAttr(def);
    }
}

static Attr* find_attr(const std::vector<AttrPtr>* al, AttrTag tag) {
    if ( ! al )
        return nullptr;

    for ( size_t i = 0; i < al->size(); ++i )
        if ( (*al)[i]->Tag() == tag )
            return (*al)[i].get();

    return nullptr;
}

static std::optional<FuncType::Prototype> func_type_check(const FuncType* decl, const FuncType* impl) {
    if ( decl->Flavor() != impl->Flavor() ) {
        impl->Error("incompatible function flavor", decl);
        return {};
    }

    if ( impl->Flavor() == FUNC_FLAVOR_FUNCTION ) {
        if ( same_type(decl, impl) )
            return decl->Prototypes()[0];

        impl->Error("incompatible function types", decl);
        return {};
    }

    auto rval = decl->FindPrototype(*impl->Params());

    if ( rval )
        for ( auto i = 0; i < rval->args->NumFields(); ++i )
            if ( auto ad = rval->args->FieldDecl(i)->GetAttr(ATTR_DEPRECATED) ) {
                auto msg = ad->DeprecationMessage();

                if ( ! msg.empty() )
                    msg = ": " + msg;

                reporter->Deprecation(util::fmt("use of deprecated parameter '%s'%s (%s)", rval->args->FieldName(i),
                                                msg.data(), obj_desc_short(impl).c_str()),
                                      impl->GetLocationInfo(), decl->GetLocationInfo());
            }

    return rval;
}

static bool canonical_arg_types_match(const FuncType* decl, const FuncType* impl) {
    const auto& canon_args = decl->Params();
    const auto& impl_args = impl->Params();

    if ( canon_args->NumFields() != impl_args->NumFields() )
        return false;

    for ( auto i = 0; i < canon_args->NumFields(); ++i )
        if ( ! same_type(canon_args->GetFieldType(i), impl_args->GetFieldType(i)) )
            return false;

    return true;
}

static auto get_prototype(IDPtr id, FuncTypePtr t) {
    auto decl = id->GetType()->AsFuncType();
    auto prototype = func_type_check(decl, t.get());

    if ( prototype ) {
        if ( decl->Flavor() == FUNC_FLAVOR_FUNCTION ) {
            // If a previous declaration of the function had
            // &default params, automatically transfer any that
            // are missing (convenience so that implementations
            // don't need to specify the &default expression again).
            transfer_arg_defaults(prototype->args.get(), t->Params().get());
        }
        else {
            // Warn for trying to use &default parameters in
            // hook/event handler body when it already has a
            // declaration since only &default in the declaration
            // has any effect.
            const auto& args = t->Params();

            for ( int i = 0; i < args->NumFields(); ++i ) {
                auto f = args->FieldDecl(i);

                if ( f->attrs && f->attrs->Find(ATTR_DEFAULT) ) {
                    reporter->PushLocation(args->GetLocationInfo());
                    reporter->Warning("&default on parameter '%s' has no effect (not a %s declaration)",
                                      args->FieldName(i), t->FlavorString().data());
                    reporter->PopLocation();
                }
            }
        }

        if ( prototype->deprecated ) {
            auto msg = prototype->deprecation_msg;
            if ( ! msg.empty() )
                msg = ": " + msg;

            reporter->Deprecation(util::fmt("use of deprecated '%s' prototype%s (%s)", id->Name(), msg.c_str(),
                                            obj_desc_short(t.get()).c_str()),
                                  t->GetLocationInfo(), prototype->args->GetLocationInfo());
        }
    }

    else {
        // Allow renaming arguments, but only for the canonical
        // prototypes of hooks/events.
        if ( canonical_arg_types_match(decl, t.get()) )
            prototype = decl->Prototypes()[0];
        else
            t->Error("use of undeclared alternate prototype", id.get());
    }

    return prototype;
}

static bool check_params(int i, std::optional<FuncType::Prototype> prototype, const RecordTypePtr& args,
                         const RecordTypePtr& canon_args, const char* module_name) {
    TypeDecl* arg_i;
    bool hide = false;

    if ( prototype ) {
        auto it = prototype->offsets.find(i);

        if ( it == prototype->offsets.end() ) {
            // Alternate prototype hides this param
            hide = true;
            arg_i = canon_args->FieldDecl(i);
        }
        else {
            // Alternate prototype maps this param to another index
            arg_i = args->FieldDecl(it->second);
        }
    }
    else {
        if ( i < args->NumFields() )
            arg_i = args->FieldDecl(i);
        else
            return false;
    }

    auto arg_id = lookup_ID(arg_i->id, module_name);

    if ( arg_id && ! arg_id->IsGlobal() )
        arg_id->Error("argument name used twice");

    const char* local_name = arg_i->id;

    if ( hide )
        // Note the illegal '-' in hidden name implies we haven't
        // clobbered any local variable names.
        local_name = util::fmt("%s-hidden", local_name);

    arg_id = install_ID(local_name, module_name, false, false);
    arg_id->SetType(arg_i->type);

    return true;
}

void begin_func(IDPtr id, const char* module_name, FunctionFlavor flavor, bool is_redef, FuncTypePtr t,
                std::unique_ptr<std::vector<AttrPtr>> attrs) {
    if ( flavor == FUNC_FLAVOR_EVENT ) {
        const auto& yt = t->Yield();

        if ( yt && yt->Tag() != TYPE_VOID )
            id->Error("event cannot yield a value", t.get());

        t->ClearYieldType(flavor);

        if ( ! event_registry->Lookup(id->Name()) )
            register_new_event(id);
    }

    std::optional<FuncType::Prototype> prototype;

    if ( id->GetType() ) {
        if ( id->GetType()->Tag() != TYPE_FUNC ) {
            id->Error("Function clash with previous definition with incompatible type", t.get());
            reporter->FatalError("invalid definition of '%s' (see previous errors)", id->Name());
        }
        prototype = get_prototype(id, t);
    }
    else if ( is_redef )
        id->Error("redef of not-previously-declared value");

    if ( id->HasVal() ) {
        FunctionFlavor id_flavor = id->GetVal()->AsFunc()->Flavor();

        if ( id_flavor != flavor )
            id->Error("inconsistent function flavor", t.get());

        switch ( id_flavor ) {
            case FUNC_FLAVOR_EVENT:
            case FUNC_FLAVOR_HOOK:
                if ( is_redef )
                    // Clear out value so it will be replaced.
                    id->SetVal(nullptr);
                break;

            case FUNC_FLAVOR_FUNCTION:
                if ( ! id->IsRedefinable() )
                    id->Error("already defined", t.get());
                break;

            default: reporter->InternalError("invalid function flavor"); break;
        }
    }
    else
        id->SetType(t);

    if ( IsErrorType(id->GetType()->Tag()) )
        reporter->FatalError("invalid definition of '%s' (see previous errors)", id->Name());

    const auto& args = t->Params();
    const auto& canon_args = id->GetType()->AsFuncType()->Params();

    push_scope(std::move(id), std::move(attrs));

    for ( int i = 0; i < canon_args->NumFields(); ++i )
        if ( ! check_params(i, prototype, args, canon_args, module_name) )
            break;

    if ( Attr* depr_attr = find_attr(current_scope()->Attrs().get(), ATTR_DEPRECATED) )
        current_scope()->GetID()->MakeDeprecated(depr_attr->GetExpr());

    // Reset the AST node statistics to track afresh for this function.
    Stmt::ResetNumStmts();
    Expr::ResetNumExprs();
}

class OuterIDBindingFinder : public TraversalCallback {
public:
    OuterIDBindingFinder(ScopePtr s) { scopes.emplace_back(s); }

    TraversalCode PreExpr(const Expr*) override;
    TraversalCode PostExpr(const Expr*) override;

    std::vector<ScopePtr> scopes;
    std::unordered_set<ID*> outer_id_references;
};

TraversalCode OuterIDBindingFinder::PreExpr(const Expr* expr) {
    if ( expr->Tag() == EXPR_LAMBDA ) {
        auto le = static_cast<const LambdaExpr*>(expr);
        scopes.emplace_back(le->GetScope());
        return TC_CONTINUE;
    }

    if ( expr->Tag() != EXPR_NAME )
        return TC_CONTINUE;

    auto e = static_cast<const NameExpr*>(expr);
    auto id = e->Id();

    if ( id->IsGlobal() )
        return TC_CONTINUE;

    for ( const auto& scope : scopes )
        if ( scope->Find(id->Name()) )
            // Shadowing is not allowed, so if it's found at inner scope, it's
            // not something we have to worry about also being at outer scope.
            return TC_CONTINUE;

    outer_id_references.insert(id);
    return TC_CONTINUE;
}

TraversalCode OuterIDBindingFinder::PostExpr(const Expr* expr) {
    if ( expr->Tag() == EXPR_LAMBDA )
        scopes.pop_back();

    return TC_CONTINUE;
}

// The following is only used for debugging AST duplication.  If activated,
// each AST is replaced with its duplicate.  In the absence of a duplication
// error, this shouldn't change any semantics, so running the test suite
// with this variable set can find flaws in the duplication machinery.
static bool duplicate_ASTs = getenv("ZEEK_DUPLICATE_ASTS");

void end_func(StmtPtr body, const char* module_name, bool free_of_conditionals) {
    if ( duplicate_ASTs && reporter->Errors() == 0 )
        // Only try duplication in the absence of errors.  If errors
        // have occurred, they can be re-generated during the
        // duplication process, leading to regression failures due
        // to duplicated error messages.
        //
        // We duplicate twice to make sure that the AST produced
        // by duplicating can itself be correctly duplicated.
        body = body->Duplicate()->Duplicate();

    auto oi = body->GetOptInfo();
    oi->is_free_of_conditionals = free_of_conditionals;
    oi->num_stmts = Stmt::GetNumStmts();
    oi->num_exprs = Expr::GetNumExprs();

    auto ingredients = std::make_unique<FunctionIngredients>(pop_scope(), std::move(body), module_name);
    auto id = ingredients->GetID();
    if ( ! id->HasVal() ) {
        auto f = make_intrusive<ScriptFunc>(id);
        id->SetVal(make_intrusive<FuncVal>(std::move(f)));
        id->SetConst();
    }

    id->GetVal()->AsFunc()->AddBody(*ingredients);

    if ( ! analysis_options.gen_ZAM )
        script_coverage_mgr.AddFunction(id, ingredients->Body());

    auto func_ptr = cast_intrusive<FuncVal>(id->GetVal())->AsFuncPtr();
    auto func = cast_intrusive<ScriptFunc>(func_ptr);
    func->SetScope(ingredients->Scope());

    for ( const auto& group : ingredients->Groups() )
        group->AddFunc(func);

    analyze_func(std::move(func));

    // Note: ideally, something would take ownership of this memory until the
    // end of script execution, but that's essentially the same as the
    // lifetime of the process at the moment, so ok to "leak" it.
    ingredients.release();
}

IDPList gather_outer_ids(ScopePtr scope, StmtPtr body) {
    OuterIDBindingFinder cb(scope);
    body->Traverse(&cb);

    IDPList idl;

    for ( auto id : cb.outer_id_references )
        idl.append(id);

    return idl;
}

} // namespace zeek::detail
