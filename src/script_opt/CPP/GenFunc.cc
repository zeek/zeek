// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail {

using namespace std;

void CPPCompile::CompileFunc(const FuncInfo& func) {
    if ( ! IsCompilable(func) )
        return;

    auto fname = Canonicalize(BodyName(func)) + "_zf";
    auto pf = func.Profile();
    auto f = func.Func();
    const auto& body = func.Body();

    DefineBody(f->GetType(), pf, fname, body, nullptr, f->Flavor());
}

void CPPCompile::CompileLambda(const LambdaExpr* l, const ProfileFunc* pf) {
    auto lname = Canonicalize(l->Name()) + "_lb";
    auto body = l->Ingredients()->Body();
    auto l_id = l->Ingredients()->GetID();
    auto& ids = l->OuterIDs();

    DefineBody(l_id->GetType<FuncType>(), pf, lname, body, &ids, FUNC_FLAVOR_FUNCTION);
}

void CPPCompile::GenInvokeBody(const string& call, const TypePtr& t) {
    if ( ! t || t->Tag() == TYPE_VOID ) {
        Emit("%s;", call);
        Emit("return nullptr;");
    }
    else
        Emit("return %s;", NativeToGT(call, t, GEN_VAL_PTR));
}

void CPPCompile::DefineBody(const FuncTypePtr& ft, const ProfileFunc* pf, const string& fname, const StmtPtr& body,
                            const IDPList* lambda_ids, FunctionFlavor flavor) {
    IDPList l_ids;
    if ( lambda_ids )
        l_ids = *lambda_ids;

    locals.clear();
    params.clear();

    body_name = fname;

    func_type = ft;
    ret_type = ft->Yield();

    in_hook = flavor == FUNC_FLAVOR_HOOK;
    auto ret_type_str = in_hook ? "bool" : FullTypeName(ret_type);

    for ( const auto& p : pf->Params() )
        params.emplace(p);

    NL();

    Emit("%s %s(%s)", ret_type_str, fname, ParamDecl(ft, &l_ids, pf));

    StartBlock();

    // Deal with "any" parameters, if any.
    TranslateAnyParams(ft, pf);

    // Make sure that any events referred to in this function have
    // been initialized.
    InitializeEvents(pf);

    // Create the local variables.
    DeclareLocals(pf, &l_ids);

    GenStmt(body);

    if ( in_hook ) {
        Emit("return true;");
        in_hook = false;
    }

    // Seatbelts for running off the end of a function that's supposed
    // to return a non-native type.
    if ( ! IsNativeType(ret_type) )
        Emit("return nullptr;");

    EndBlock();
}

void CPPCompile::TranslateAnyParams(const FuncTypePtr& ft, const ProfileFunc* pf) {
    const auto& formals = ft->Params();
    int n = formals->NumFields();

    for ( auto i = 0; i < n; ++i ) {
        const auto& t = formals->GetFieldType(i);
        if ( t->Tag() != TYPE_ANY )
            // Not a relevant parameter.
            continue;

        auto param_id = FindParam(i, pf);
        if ( ! param_id )
            // Parameter isn't used, skip it.
            continue;

        const auto& pt = param_id->GetType();
        if ( pt->Tag() == TYPE_ANY )
            // It's already "any", nothing more to do.
            continue;

        auto any_i = string("any_param__CPP_") + Fmt(i);

        Emit("%s %s = %s;", FullTypeName(pt), LocalName(param_id), GenericValPtrToGT(any_i, pt, GEN_NATIVE));
    }
}

void CPPCompile::InitializeEvents(const ProfileFunc* pf) {
    // Make sure that any events referred to in this function have
    // been initialized.  We have to do this dynamically because it
    // depends on whether the final script using the compiled code
    // happens to load the associated event handler
    for ( const auto& e : pf->Events() ) {
        auto ev_name = globals[e] + "_ev";

        // Create a scope so we don't have to individualize the
        // variables.
        Emit("{");
        Emit("static bool did_init = false;");
        Emit("if ( ! did_init )");
        StartBlock();

        // We do both a Lookup and a Register because only the latter
        // returns an EventHandlerPtr, sigh.
        Emit("if ( event_registry->Lookup(\"%s\") )", e);
        StartBlock();
        Emit("%s = event_registry->Register(\"%s\");", ev_name, e);
        EndBlock();
        Emit("did_init = true;");
        EndBlock();
        Emit("}");
    }
}

void CPPCompile::DeclareLocals(const ProfileFunc* pf, const IDPList* lambda_ids) {
    // We track captures by their names rather than their ID*'s because the
    // latter can be inconsistent when inlining.
    set<string> capture_names;
    if ( lambda_ids )
        for ( auto li : *lambda_ids )
            capture_names.insert(CaptureName(li));

    const auto& ls = pf->Locals();
    int num_params = static_cast<int>(pf->Params().size());

    // Track whether we generated a declaration.  This is just for
    // tidiness in the output.
    bool did_decl = false;

    for ( const auto& l : ls ) {
        auto ln = LocalName(l);
        auto cn = CaptureName(l);

        if ( capture_names.count(cn) > 0 )
            // No need to declare these, they're passed in as parameters.
            ln = cn;

        else if ( params.count(l) == 0 && l->Offset() >= num_params ) { // Not a parameter, so must be a local.
            Emit("%s %s;", FullTypeName(l->GetType()), ln);
            did_decl = true;
        }

        locals.emplace(l, ln);
    }

    if ( did_decl )
        NL();
}

string CPPCompile::BodyName(const FuncInfo& func) {
    const auto& f = func.Func();
    const auto& body = func.Body();
    auto fname = f->GetName();

    // Extend name with location information.
    auto loc = body->GetLocationInfo();
    if ( loc->FileName() ) {
        auto fn = loc->FileName();

        // Skip leading goop that gets added by search paths.
        while ( *fn == '.' || *fn == '/' )
            ++fn;

        auto canonicalize = [](char c) -> char { return isalnum(c) ? c : '_'; };

        string fns = fn;
        std::ranges::transform(fns, fns.begin(), canonicalize);

        if ( ! isalpha(fns[0]) )
            // This can happen for filenames beginning with numbers.
            fns = "_" + fns;

        fname = fns + "__" + fname;
    }

    const auto& bodies = f->GetBodies();

    if ( bodies.size() == 1 )
        return fname;

    // Make the name distinct-per-body.

    size_t i;
    for ( i = 0; i < bodies.size(); ++i )
        if ( bodies[i].stmts == body )
            break;

    if ( i >= bodies.size() )
        reporter->InternalError("can't find body in CPPCompile::BodyName");

    return fname + "__" + Fmt(static_cast<int>(i));
}

p_hash_type CPPCompile::BodyHash(const Stmt* body) {
    auto bn = body_names.find(body);
    ASSERT(bn != body_names.end());

    auto& body_name = bn->second;
    auto bh = body_hashes.find(body_name);
    ASSERT(bh != body_hashes.end());

    return bh->second;
}

string CPPCompile::GenArgs(const RecordTypePtr& params, const Expr* e) {
    const auto& exprs = e->AsListExpr()->Exprs();
    string gen;

    int n = exprs.size();

    for ( auto i = 0; i < n; ++i ) {
        auto e_i = exprs[i];
        auto gt = GEN_NATIVE;

        const auto& param_t = params->GetFieldType(i);
        bool param_any = param_t->Tag() == TYPE_ANY;
        bool arg_any = e_i->GetType()->Tag() == TYPE_ANY;

        if ( param_any && ! arg_any )
            gt = GEN_VAL_PTR;

        auto expr_gen = GenExpr(e_i, gt);

        if ( ! param_any && arg_any )
            expr_gen = GenericValPtrToGT(expr_gen, param_t, GEN_NATIVE);

        gen += expr_gen;
        if ( i < n - 1 )
            gen += ", ";
    }

    return gen;
}

} // namespace zeek::detail
