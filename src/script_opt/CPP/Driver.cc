// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>

#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/IDOptInfo.h"

extern std::unordered_set<std::string> files_with_conditionals;

namespace zeek::detail {

using namespace std;

CPPCompile::CPPCompile(vector<FuncInfo>& _funcs, std::shared_ptr<ProfileFuncs> _pfs, const string& gen_name,
                       bool _standalone, bool report_uncompilable)
    : funcs(_funcs), pfs(std::move(_pfs)), standalone(_standalone) {
    auto target_name = gen_name.c_str();

    write_file = fopen(target_name, "w");
    if ( ! write_file ) {
        reporter->Error("can't open C++ target file %s", target_name);
        exit(1);
    }

    Compile(report_uncompilable);
}

CPPCompile::~CPPCompile() { fclose(write_file); }

void CPPCompile::Compile(bool report_uncompilable) {
    unordered_set<const Type*> rep_types;
    unordered_set<string> filenames_reported_as_skipped;
    unordered_set<const Attr*> attrs;
    bool had_to_skip = false;

    for ( auto& func : funcs )
        if ( ! AnalyzeFuncBody(func, filenames_reported_as_skipped, rep_types, report_uncompilable) )
            had_to_skip = true;

    if ( standalone ) {
        if ( had_to_skip )
            reporter->FatalError("aborting standalone compilation to C++ due to having to skip some functions");

        for ( auto& g : global_scope()->OrderedVars() ) {
            bool compiled_global = obj_matches_opt_files(g) == AnalyzeDecision::SHOULD;

            if ( ! compiled_global )
                for ( const auto& i_e : g->GetOptInfo()->GetInitExprs() )
                    if ( obj_matches_opt_files(i_e) == AnalyzeDecision::SHOULD ) {
                        compiled_global = true;
                        break;
                    }

            if ( ! compiled_global )
                continue;

            // We will need to generate this global's definition, including
            // its initialization. Make sure we're tracking it and its
            // associated types, including those required for initializing.
            auto& t = g->GetType();
            (void)pfs->HashType(t);
            rep_types.insert(TypeRep(t));

            all_accessed_globals.insert(g.get());
            accessed_globals.insert(g.get());

            for ( const auto& i_e : g->GetOptInfo()->GetInitExprs() ) {
                auto pf = std::make_shared<ProfileFunc>(i_e.get());
                for ( auto& t : pf->OrderedTypes() ) {
                    (void)pfs->HashType(t);
                    rep_types.insert(TypeRep(t));
                }
                for ( auto& g : pf->Globals() )
                    accessed_globals.insert(g);
                for ( auto& ag : pf->AllGlobals() )
                    all_accessed_globals.insert(ag);
            }
        }

        for ( auto& l : pfs->Lambdas() )
            if ( obj_matches_opt_files(l) == AnalyzeDecision::SHOULD )
                accessed_lambdas.insert(l);

        for ( auto& ea : pfs->ExprAttrs() )
            if ( obj_matches_opt_files(ea.first) == AnalyzeDecision::SHOULD ) {
                auto& attr = ea.first;
                attrs.insert(attr);
                auto& t = attr->GetExpr()->GetType();
                rep_types.insert(TypeRep(t));
            }
    }

    auto t = util::current_time();
    total_hash = merge_p_hashes(total_hash, hash<double>{}(t));

    GenProlog();

    // Track all of the types we'll be using.
    for ( const auto& t : rep_types ) {
        TypePtr tp{NewRef{}, (Type*)(t)};
        types.AddKey(tp, pfs->HashType(t));
    }

    NL();

    for ( auto& g : all_accessed_globals )
        CreateGlobal(g);

    for ( const auto& e : accessed_events )
        if ( AddGlobal(e, "gl") )
            Emit("EventHandlerPtr %s_ev;", globals[string(e)]);

    for ( const auto& t : rep_types ) {
        ASSERT(types.HasKey(t));
        TypePtr tp{NewRef{}, const_cast<Type*>(t)};
        RegisterType(tp);
    }

    for ( const auto& attr : attrs ) {
        AttrPtr attr_p = {NewRef{}, const_cast<Attr*>(attr)};
        (void)RegisterAttr(attr_p);
    }

    // The scaffolding is now in place to go ahead and generate
    // the functions & lambdas.  First declare them ...
    for ( const auto& func : funcs )
        if ( ! func.ShouldSkip() )
            DeclareFunc(func);

    // We track lambdas by their internal names, and associate those
    // with their AST bodies.  Two different LambdaExpr's can wind up
    // referring to the same underlying lambda if the bodies happen to
    // be identical.  In that case, we don't want to generate the lambda
    // twice, but we do want to map the second one to the same body name.
    unordered_map<string, const Stmt*> lambda_ASTs;
    for ( const auto& l : accessed_lambdas ) {
        const auto& n = l->Name();
        const auto body = l->Ingredients()->Body().get();
        if ( lambda_ASTs.count(n) > 0 )
            // Reuse previous body.
            body_names[body] = body_names[lambda_ASTs[n]];
        else {
            DeclareLambda(l, pfs->ExprProf(l).get());
            lambda_ASTs[n] = body;
        }
    }

    NL();

    // ... and now generate their bodies.
    for ( const auto& func : funcs )
        if ( ! func.ShouldSkip() )
            CompileFunc(func);

    lambda_ASTs.clear();
    for ( const auto& l : accessed_lambdas ) {
        const auto& n = l->Name();
        if ( lambda_ASTs.count(n) > 0 )
            continue;

        CompileLambda(l, pfs->ExprProf(l).get());
        lambda_ASTs[n] = l->Ingredients()->Body().get();
    }

    NL();
    Emit("std::vector<CPP_RegisterBody> CPP__bodies_to_register = {");

    for ( const auto& f : compiled_funcs )
        RegisterCompiledBody(f);

    Emit("};");

    if ( standalone )
        // Now that we've identified all of the record fields we might have
        // to generate, make sure we track their attributes.
        for ( const auto& fd : field_decls ) {
            auto td = fd.second;
            if ( obj_matches_opt_files(td->type) == AnalyzeDecision::SHOULD ) {
                TypePtr tp = {NewRef{}, const_cast<Type*>(TypeRep(td->type))};
                RegisterType(tp);
            }
            if ( obj_matches_opt_files(td->attrs) == AnalyzeDecision::SHOULD )
                RegisterAttributes(td->attrs);
        }

    GenEpilog();
}

bool CPPCompile::AnalyzeFuncBody(FuncInfo& fi, unordered_set<string>& filenames_reported_as_skipped,
                                 unordered_set<const Type*>& rep_types, bool report_uncompilable) {
    const auto& f = fi.Func();
    auto& body = fi.Body();

    string fn = body->GetLocationInfo()->FileName();

    if ( fi.ShouldAnalyze() && fi.ShouldSkip() ) {
        const char* reason = nullptr;
        auto is_compilable = is_CPP_compilable(fi.Profile(), &reason);
        ASSERT(! is_compilable);
        ASSERT(reason);
        if ( standalone || report_uncompilable )
            reporter->Warning("%s cannot be compiled to C++ due to %s", f->GetName().c_str(), reason);

        fi.SetSkip(true);
        if ( standalone )
            return false;
    }

    if ( ! analysis_options.allow_cond && ! fi.ShouldSkip() ) {
        if ( ! analysis_options.only_files.empty() && files_with_conditionals.count(fn) > 0 ) {
            if ( report_uncompilable )
                reporter->Warning("%s cannot be compiled to C++ due to source file %s having conditional code",
                                  f->GetName().c_str(), fn.c_str());

            else if ( filenames_reported_as_skipped.count(fn) == 0 ) {
                reporter->Warning("skipping compilation of files in %s due to presence of conditional code",
                                  fn.c_str());
                filenames_reported_as_skipped.emplace(fn);
            }

            fi.SetSkip(true);
        }
    }

    if ( fi.ShouldSkip() ) {
        not_fully_compilable.insert(f->GetName());
        return true;
    }

    auto pf = fi.Profile();
    total_hash = merge_p_hashes(total_hash, pf->HashVal());

    for ( auto t : pf->UnorderedTypes() )
        rep_types.insert(pfs->TypeRep(t));

    auto& pf_all_gl = pf->AllGlobals();
    all_accessed_globals.insert(pf_all_gl.begin(), pf_all_gl.end());

    auto& pf_gl = pf->Globals();
    accessed_globals.insert(pf_gl.begin(), pf_gl.end());

    auto& pf_events = pf->Events();
    accessed_events.insert(pf_events.begin(), pf_events.end());

    auto& pf_lambdas = pf->Lambdas();
    accessed_lambdas.insert(pf_lambdas.begin(), pf_lambdas.end());

    if ( is_lambda(f) || is_when_lambda(f) ) {
        // We deal with these separately.
        fi.SetSkip(true);
        return true;
    }

    const char* reason;
    if ( IsCompilable(fi, &reason) ) {
        if ( f->Flavor() == FUNC_FLAVOR_FUNCTION )
            // Note this as a callable compiled function.
            compilable_funcs.insert(BodyName(fi));
    }
    else {
        if ( reason && (standalone || report_uncompilable) ) {
            reporter->Warning("%s cannot be compiled to C++ due to %s", f->GetName().c_str(), reason);
        }

        not_fully_compilable.insert(f->GetName());
        return false;
    }

    return true;
}

void CPPCompile::GenProlog() {
    Emit("#include \"zeek/script_opt/CPP/Runtime.h\"\n");

    // Get the working directory for annotating the output to help
    // with debugging.
    char working_dir[8192];
    if ( ! getcwd(working_dir, sizeof working_dir) )
        reporter->FatalError("getcwd failed: %s", strerror(errno));

    Emit("namespace zeek::detail { //\n");
    Emit("namespace CPP_%s { // %s\n", Fmt(total_hash), string(working_dir));

    // The following might-or-might-not wind up being populated/used.
    Emit("std::vector<zeek_int_t> field_mapping;");
    Emit("std::vector<zeek_int_t> enum_mapping;");
    NL();

    const_info[TYPE_BOOL] = CreateConstInitInfo("Bool", "ValPtr", "bool");
    const_info[TYPE_INT] = CreateConstInitInfo("Int", "ValPtr", "zeek_int_t");
    const_info[TYPE_COUNT] = CreateConstInitInfo("Count", "ValPtr", "zeek_uint_t");
    const_info[TYPE_DOUBLE] = CreateConstInitInfo("Double", "ValPtr", "double");
    const_info[TYPE_TIME] = CreateConstInitInfo("Time", "ValPtr", "double");
    const_info[TYPE_INTERVAL] = CreateConstInitInfo("Interval", "ValPtr", "double");
    const_info[TYPE_ADDR] = CreateConstInitInfo("Addr", "ValPtr", "");
    const_info[TYPE_SUBNET] = CreateConstInitInfo("SubNet", "ValPtr", "");
    const_info[TYPE_PORT] = CreateConstInitInfo("Port", "ValPtr", "uint32_t");

    const_info[TYPE_ENUM] = CreateCompoundInitInfo("Enum", "ValPtr");
    const_info[TYPE_STRING] = CreateCompoundInitInfo("String", "ValPtr");
    const_info[TYPE_LIST] = CreateCompoundInitInfo("List", "ValPtr");
    const_info[TYPE_PATTERN] = CreateCompoundInitInfo("Pattern", "ValPtr");
    const_info[TYPE_VECTOR] = CreateCompoundInitInfo("Vector", "ValPtr");
    const_info[TYPE_RECORD] = CreateCompoundInitInfo("Record", "ValPtr");
    const_info[TYPE_TABLE] = CreateCompoundInitInfo("Table", "ValPtr");
    const_info[TYPE_FUNC] = CreateCompoundInitInfo("Func", "ValPtr");
    const_info[TYPE_FILE] = CreateCompoundInitInfo("File", "ValPtr");
    const_info[TYPE_TYPE] = CreateCompoundInitInfo("TypeVal", "Ptr");

    type_info = CreateCompoundInitInfo("Type", "Ptr");
    attr_info = CreateCompoundInitInfo("Attr", "Ptr");
    attrs_info = CreateCompoundInitInfo("Attributes", "Ptr");

    call_exprs_info = CreateCustomInitInfo("CallExpr", "Ptr");
    lambda_reg_info = CreateCustomInitInfo("LambdaRegistration", "");
    global_id_info = CreateCustomInitInfo("GlobalID", "");

    NL();
    DeclareDynCPPStmt();
    NL();
}

shared_ptr<CPP_InitsInfo> CPPCompile::CreateConstInitInfo(const char* tag, const char* type, const char* c_type) {
    auto gi = make_shared<CPP_BasicConstInitsInfo>(tag, type, c_type);
    return RegisterInitInfo(tag, type, gi);
}

shared_ptr<CPP_InitsInfo> CPPCompile::CreateCompoundInitInfo(const char* tag, const char* type) {
    auto gi = make_shared<CPP_CompoundInitsInfo>(tag, type);
    return RegisterInitInfo(tag, type, gi);
}

shared_ptr<CPP_InitsInfo> CPPCompile::CreateCustomInitInfo(const char* tag, const char* type) {
    auto gi = make_shared<CPP_CustomInitsInfo>(tag, type);
    if ( type[0] == '\0' )
        gi->SetCPPType("void*");

    return RegisterInitInfo(tag, type, gi);
}

shared_ptr<CPP_InitsInfo> CPPCompile::RegisterInitInfo(const char* tag, const char* type,
                                                       shared_ptr<CPP_InitsInfo> gi) {
    string v_type = type[0] ? (string(tag) + type) : "void*";
    Emit("std::vector<%s> CPP__%s__;", v_type, string(tag));
    all_global_info.insert(gi);
    return gi;
}

void CPPCompile::RegisterCompiledBody(const string& f) {
    // Build up an initializer of the events relevant to the function.
    string events;
    auto be = body_events.find(f);
    if ( be != body_events.end() )
        for ( const auto& e : be->second ) {
            if ( ! events.empty() )
                events += ", ";

            events += "\"";
            events += e;
            events += "\"";
        }

    events = string("{") + events + "}";

    auto fi = func_index.find(f);
    ASSERT(fi != func_index.end());
    auto type_signature = casting_index[fi->second];

    auto h = body_hashes[f];
    auto p = body_priorities[f];
    auto loc = body_locs[f];
    auto body_info = Fmt(p) + ", " + Fmt(h) + ", \"" + loc->FileName() + " (C++)\", " + Fmt(loc->FirstLine());

    Emit("\tCPP_RegisterBody(\"%s\", (void*) %s, %s, %s, std::vector<std::string>(%s)),", f, f, Fmt(type_signature),
         body_info, events);
}

void CPPCompile::GenEpilog() {
    if ( standalone ) {
        NL();
        InitializeGlobals();
    }

    NL();
    for ( const auto& ii : init_infos )
        GenInitExpr(ii.second);

    NL();
    GenCPPDynStmt();

    NL();
    for ( const auto& gi : all_global_info )
        gi->GenerateInitializers(this);

    NL();
    InitializeEnumMappings();

    NL();
    InitializeFieldMappings();

    NL();
    InitializeBiFs();

    NL();
    indices_mgr.Generate(this);

    NL();
    InitializeStrings();

    NL();
    InitializeHashes();

    NL();
    InitializeConsts();

    NL();
    GenLoadBiFs();

    NL();
    GenFinishInit();

    NL();
    GenRegisterBodies();

    NL();
    Emit("void init__CPP()");
    StartBlock();
    Emit("register_bodies__CPP();");
    EndBlock();

    if ( standalone )
        GenStandaloneActivation();

    GenInitHook();

    Emit("} //\n\n");
    Emit("} // zeek::detail");
}

void CPPCompile::GenCPPDynStmt() {
    Emit("ValPtr CPPDynStmt::Exec(Frame* f, StmtFlowType& flow)");

    StartBlock();

    Emit("flow = FLOW_RETURN;");
    Emit("f->SetOnlyCall(ce.get());");

    Emit("switch ( type_signature )");
    StartBlock();
    for ( auto i = 0U; i < func_casting_glue.size(); ++i ) {
        Emit("case %s:", to_string(i));
        StartBlock();
        auto& glue = func_casting_glue[i];

        auto invoke = string("(*(") + glue.cast + ")(func))(" + glue.args + ")";

        if ( glue.is_hook ) {
            Emit("if ( ! %s )", invoke);
            StartBlock();
            Emit("flow = FLOW_BREAK;");
            EndBlock();
            Emit("return nullptr;");
        }

        else if ( IsNativeType(glue.yield) )
            GenInvokeBody(invoke, glue.yield);

        else
            Emit("return %s;", invoke);

        EndBlock();
    }

    Emit("default:");
    Emit("\treporter->InternalError(\"invalid type in CPPDynStmt::Exec\");");
    Emit("\treturn nullptr;");

    EndBlock();
    EndBlock();
}

void CPPCompile::GenLoadBiFs() {
    Emit("void load_BiFs__CPP()");
    StartBlock();
    Emit("for ( auto& b : CPP__BiF_lookups__ )");
    Emit("\tb.ResolveBiF();");
    EndBlock();
}

void CPPCompile::GenFinishInit() {
    Emit("void finish_init__CPP()");

    StartBlock();

    Emit("static bool did_init = false;");
    Emit("if ( did_init )");
    Emit("\treturn;");
    Emit("did_init = true;");

    NL();
    Emit("std::vector<std::vector<int>> InitIndices;");
    Emit("generate_indices_set(CPP__Indices__init, InitIndices);");

    Emit("std::map<TypeTag, std::shared_ptr<CPP_AbstractInitAccessor>> InitConsts;");

    NL();
    for ( const auto& ci : const_info ) {
        auto& gi = ci.second;
        Emit("InitConsts.emplace(%s, std::make_shared<CPP_InitAccessor<%s>>(%s));", TypeTagName(ci.first),
             gi->CPPType(), gi->InitsName());
    }

    Emit(
        "InitsManager im(CPP__ConstVals, InitConsts, InitIndices, CPP__Strings, CPP__Hashes, "
        "CPP__Type__, CPP__Attributes__, CPP__Attr__, CPP__CallExpr__);");

    NL();
    int max_cohort = 0;
    for ( const auto& gi : all_global_info )
        max_cohort = std::max(max_cohort, gi->MaxCohort());

    for ( auto c = 0; c <= max_cohort; ++c )
        for ( const auto& gi : all_global_info )
            if ( gi->CohortSize(c) > 0 )
                Emit("%s.InitializeCohort(&im, %s);", gi->InitializersName(), Fmt(c));

    // Populate mappings for dynamic offsets.
    NL();
    Emit("for ( auto& em : CPP__enum_mappings__ )");
    Emit("\tenum_mapping.push_back(em.ComputeOffset(&im));");
    NL();
    Emit("for ( auto& fm : CPP__field_mappings__ )");
    Emit("\tfield_mapping.push_back(fm.ComputeOffset(&im));");

    NL();

    Emit("load_BiFs__CPP();");

    if ( standalone )
        // Note, BiFs will also be loaded again later, because the
        // main initialization finishes upon loading of the activation
        // script, rather than after all scripts have been parsed
        // and plugins (with BiFs) have been loaded.
        Emit("init_globals__CPP();");

    EndBlock();
}

void CPPCompile::GenRegisterBodies() {
    Emit("void register_bodies__CPP()");
    StartBlock();

    Emit("for ( auto& b : CPP__bodies_to_register )");
    StartBlock();
    Emit(
        "auto f = make_intrusive<CPPDynStmt>(b.func_name.c_str(), b.func, b.type_signature, "
        "b.filename, b.line_num);");

    auto reg = standalone ? "register_standalone_body" : "register_body";
    Emit("%s__CPP(f, b.priority, b.h, b.events, finish_init__CPP);", reg);
    EndBlock();

    EndBlock();
}

bool CPPCompile::IsCompilable(const FuncInfo& func, const char** reason) {
    if ( ! is_CPP_compilable(func.Profile(), reason) )
        return false;

    if ( reason )
        // Indicate that there's no fundamental reason it can't be
        // compiled.
        *reason = nullptr;

    if ( func.ShouldSkip() )
        return false;

    return true;
}

} // namespace zeek::detail
