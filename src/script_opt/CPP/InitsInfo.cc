// See the file "COPYING" in the main distribution directory for copyright.

#include <regex>

#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/CPP/AttrExprType.h"
#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/CPP/RuntimeInits.h"
#include "zeek/script_opt/IDOptInfo.h"

using namespace std;

namespace zeek::detail {

string CPP_InitsInfo::Name(int index) const { return base_name + "[" + Fmt(index) + "]"; }

void CPP_InitsInfo::GetCohortIDs(int c, std::vector<IDPtr>& ids) const {
    if ( c > MaxCohort() )
        return;

    for ( auto& co : instances[c] )
        if ( auto id = co->InitIdentifier() )
            ids.emplace_back(std::move(id));
}

void CPP_InitsInfo::AddInstance(shared_ptr<CPP_InitInfo> g) {
    auto final_init_cohort = g->FinalInitCohort();

    if ( static_cast<int>(instances.size()) <= final_init_cohort )
        instances.resize(final_init_cohort + 1);

    g->SetOffset(this, size++);

    instances[final_init_cohort].push_back(std::move(g));
}

string CPP_InitsInfo::Declare() const { return string("std::vector<") + CPPType() + "> " + base_name + ";"; }

void CPP_InitsInfo::GenerateInitializers(CPPCompile* c) {
    BuildOffsetSet(c);

    c->NL();

    auto gt = InitsType();

    // Declare the initializer.
    c->Emit("%s %s = %s(%s, %s,", gt, InitializersName(), gt, base_name, Fmt(offset_set));

    c->IndentUp();
    GenerateCohorts(c);
    c->IndentDown();

    c->Emit(");");
}

void CPP_InitsInfo::GenerateCohorts(CPPCompile* c) {
    c->Emit("{");

    int n = 0;

    // Add each cohort as a vector element.
    for ( auto& cohort : instances ) {
        if ( ++n > 1 )
            c->Emit("");

        if ( cohort.size() == 1 && ! UsesCompoundVectors() )
            BuildCohort(c, cohort);
        else {
            c->Emit("{");
            BuildCohort(c, cohort);
            c->Emit("},");
        }
    }

    c->Emit("}");
}

void CPP_InitsInfo::BuildOffsetSet(CPPCompile* c) {
    vector<int> offsets_vec;

    for ( auto& cohort : instances ) {
        // Reduce the offsets used by this cohort to an
        // offset into the managed vector-of-indices global.
        vector<int> offsets;
        offsets.reserve(cohort.size());
        for ( auto& co : cohort )
            offsets.push_back(co->Offset());

        offsets_vec.push_back(c->IndMgr().AddIndices(offsets));
    }

    // Now that we have all the offsets in a vector, reduce them, too,
    // to an offset into the managed vector-of-indices global,
    offset_set = c->IndMgr().AddIndices(offsets_vec);
}

static std::string describe_initializer(const Obj* o) {
    auto od = obj_desc(o);

    // Escape any embedded comment characters.
    od = regex_replace(od, std::regex("/\\*"), "<<SLASH-STAR>>");
    od = regex_replace(od, std::regex("\\*/"), "<<STAR-SLASH>>");

    return od;
}

void CPP_InitsInfo::BuildCohort(CPPCompile* c, std::vector<std::shared_ptr<CPP_InitInfo>>& cohort) {
    for ( auto& co : cohort ) {
        vector<string> ivs;
        auto o = co->InitObj();
        if ( o )
            c->Emit("/* #%s: Initializing %s: */", Fmt(co->Offset()), describe_initializer(o));

        co->InitializerVals(ivs);
        BuildCohortElement(c, co->InitializerType(), ivs);
    }
}

void CPP_InitsInfo::BuildCohortElement(CPPCompile* c, string init_type, vector<string>& ivs) {
    string full_init;
    bool did_one = false;
    for ( auto& iv : ivs ) {
        if ( did_one )
            full_init += ", ";
        else
            did_one = true;

        full_init += iv;
    }

    c->Emit("std::make_shared<%s>(%s),", init_type, full_init);
}

void CPP_CompoundInitsInfo::GenerateInitializers(CPPCompile* c) {
    c->Emit("");
    c->Emit("static int %s_init[] = {", tag);
    int n = 0;

    c->IndentUp();

    for ( auto& cohort : instances ) {
        if ( ++n > 1 )
            c->Emit("");

        // Figure out the size of the cohort.
        for ( auto& co : cohort ) {
            auto o = co->InitObj();
            if ( o )
                c->Emit("/* #%s: Initializing %s: */", Fmt(co->Offset()), describe_initializer(o));

            vector<string> ivs;
            co->InitializerVals(ivs);
            c->Emit(Fmt(int(ivs.size())) + ",");
            BuildCohortElement(c, co->InitializerType(), ivs);
        }

        static const auto end_of_vv = Fmt(END_OF_VEC_VEC) + ",";
        c->Emit(end_of_vv);
    }

    static const auto end_of_vvv = Fmt(END_OF_VEC_VEC_VEC) + ",";
    c->Emit(end_of_vvv);

    c->IndentDown();
    c->Emit("};");

    CPP_InitsInfo::GenerateInitializers(c);
}

void CPP_CompoundInitsInfo::GenerateCohorts(CPPCompile* c) { c->Emit("%s_init", tag); }

void CPP_CompoundInitsInfo::BuildCohortElement(CPPCompile* c, string init_type, vector<string>& ivs) {
    string init_line;
    for ( auto& iv : ivs )
        init_line += iv + ",";

    c->Emit("%s", init_line);
}

void CPP_BasicConstInitsInfo::BuildCohortElement(CPPCompile* c, string init_type, vector<string>& ivs) {
    ASSERT(ivs.size() == 1);
    c->Emit(ivs[0] + ",");
}

string CPP_InitInfo::ValElem(CPPCompile* c, ValPtr v) {
    if ( v ) {
        int consts_offset;
        auto gi = c->RegisterConstant(v, consts_offset);
        init_cohort = max(init_cohort, gi->InitCohort() + 1);
        return Fmt(consts_offset);
    }
    else
        return Fmt(-1);
}

DescConstInfo::DescConstInfo(CPPCompile* c, ValPtr v) : CPP_InitInfo(v) {
    ODesc d;
    v->Describe(&d);
    auto s = c->TrackString(d.Description());
    init = Fmt(s);
}

EnumConstInfo::EnumConstInfo(CPPCompile* c, ValPtr v) : CPP_InitInfo(v) {
    auto ev = v->AsEnumVal();
    auto& ev_t = ev->GetType();
    e_type = c->TypeOffset(ev_t);
    init_cohort = c->TypeCohort(ev_t) + 1;
    e_val = v->AsEnum();
}

StringConstInfo::StringConstInfo(CPPCompile* c, ValPtr v) : CPP_InitInfo(v) {
    auto s = v->AsString();
    const char* b = reinterpret_cast<const char*>(s->Bytes());

    len = s->Len();
    chars = c->TrackString(CPPEscape(b, len));
}

PatternConstInfo::PatternConstInfo(CPPCompile* c, ValPtr v) : CPP_InitInfo(v) {
    auto re = v->AsPatternVal()->Get();
    pattern = c->TrackString(CPPEscape(re->OrigText()));
    is_case_insensitive = re->IsCaseInsensitive();
    is_single_line = re->IsSingleLine();
}

CompoundItemInfo::CompoundItemInfo(CPPCompile* _c, ValPtr v) : CPP_InitInfo(v), c(_c) {
    auto& t = v->GetType();
    type = c->TypeOffset(t);
    init_cohort = c->TypeFinalCohort(t) + 1;
}

ListConstInfo::ListConstInfo(CPPCompile* _c, ValPtr v) : CompoundItemInfo(_c) {
    auto lv = cast_intrusive<ListVal>(v);
    auto n = lv->Length();

    for ( auto i = 0; i < n; ++i )
        vals.emplace_back(ValElem(c, lv->Idx(i)));
}

VectorConstInfo::VectorConstInfo(CPPCompile* c, ValPtr v) : CompoundItemInfo(c, v) {
    auto vv = cast_intrusive<VectorVal>(v);
    auto n = vv->Size();

    for ( auto i = 0U; i < n; ++i )
        vals.emplace_back(ValElem(c, vv->ValAt(i)));
}

RecordConstInfo::RecordConstInfo(CPPCompile* c, ValPtr v) : CompoundItemInfo(c, v) {
    auto r = cast_intrusive<RecordVal>(v);
    auto n = r->NumFields();

    type = c->TypeOffset(r->GetType());

    for ( auto i = 0U; i < n; ++i )
        vals.emplace_back(ValElem(c, r->GetField(i)));
}

TableConstInfo::TableConstInfo(CPPCompile* c, ValPtr v) : CompoundItemInfo(c, v) {
    auto tv = cast_intrusive<TableVal>(v);

    auto gi = c->RegisterAttributes(tv->GetAttrs());
    int attrs = -1;
    if ( gi ) {
        init_cohort = max(init_cohort, gi->InitCohort() + 1);
        attrs = gi->Offset();
    }

    vals.emplace_back(std::to_string(attrs));

    for ( auto& tv_i : tv->ToMap() ) {
        vals.emplace_back(ValElem(c, tv_i.first));  // index
        vals.emplace_back(ValElem(c, tv_i.second)); // value
    }
}

FileConstInfo::FileConstInfo(CPPCompile* c, ValPtr v) : CompoundItemInfo(c, v) {
    auto fv = cast_intrusive<FileVal>(v);
    auto fname = c->TrackString(fv->Get()->Name());
    vals.emplace_back(Fmt(fname));
}

FuncConstInfo::FuncConstInfo(CPPCompile* _c, ValPtr v) : CompoundItemInfo(_c, v), fv(v->AsFuncVal()) {
    // This is slightly hacky.  There's a chance that this constant
    // depends on a lambda being registered.  Here we use the knowledge
    // that LambdaRegistrationInfo sets its cohort to 1 more than
    // the function type, so we can ensure any possible lambda has
    // been registered by setting ours to 2 more.  CompoundItemInfo
    // has already set our cohort to 1 more.
    ++init_cohort;
}

void FuncConstInfo::InitializerVals(std::vector<std::string>& ivs) const {
    auto f = fv->AsFunc();
    const auto& fn = f->GetName();
    const auto& bodies = f->GetBodies();

    ivs.emplace_back(Fmt(type));
    ivs.emplace_back(Fmt(c->TrackString(fn)));
    ivs.emplace_back(to_string(bodies.size()));

    if ( ! c->NotFullyCompilable(fn) ) {
        for ( const auto& b : bodies ) {
            auto h = c->BodyHash(b.stmts.get());
            auto h_o = c->TrackHash(h);
            ivs.emplace_back(Fmt(h_o));
        }
    }
}

TypeConstInfo::TypeConstInfo(CPPCompile* _c, ValPtr v) : CompoundItemInfo(_c, v) {
    auto tv = v->AsTypeVal();
    auto t = tv->GetType()->AsTypeType()->GetType();
    auto gi = c->RegisterType(t);
    type = c->TypeOffset(t);
    init_cohort = max(init_cohort, gi->InitCohort() + 1);
}

AttrInfo::AttrInfo(CPPCompile* _c, const AttrPtr& attr) : CompoundItemInfo(_c) {
    vals.emplace_back(Fmt(static_cast<int>(attr->Tag())));
    auto a_e = attr->GetExpr();

    if ( a_e ) {
        auto gi = c->RegisterType(a_e->GetType());
        if ( gi )
            init_cohort = max(init_cohort, gi->InitCohort() + 1);

        if ( ! CPPCompile::IsSimpleInitExpr(a_e) ) {
            if ( obj_matches_opt_files(a_e) != AnalyzeDecision::SHOULD_NOT ) {
                gi = c->RegisterInitExpr(a_e);
                init_cohort = max(init_cohort, gi->InitCohort() + 1);

                vals.emplace_back(Fmt(static_cast<int>(AE_CALL)));
                vals.emplace_back(Fmt(gi->Offset()));
            }
        }

        else if ( a_e->Tag() == EXPR_CONST ) {
            auto v = a_e->AsConstExpr()->ValuePtr();
            vals.emplace_back(Fmt(static_cast<int>(AE_CONST)));
            vals.emplace_back(ValElem(c, v));
        }

        else if ( a_e->Tag() == EXPR_NAME ) {
            auto g = a_e->AsNameExpr()->IdPtr();
            gi = c->RegisterGlobal(g);
            init_cohort = max(init_cohort, gi->InitCohort() + 1);

            vals.emplace_back(Fmt(static_cast<int>(AE_NAME)));
            vals.emplace_back(Fmt(c->TrackString(g->Name())));
        }

        else {
            ASSERT(a_e->Tag() == EXPR_RECORD_COERCE);
            ASSERT(gi);
            vals.emplace_back(Fmt(static_cast<int>(AE_RECORD)));
            vals.emplace_back(Fmt(gi->Offset()));
        }
    }

    else
        vals.emplace_back(Fmt(static_cast<int>(AE_NONE)));
}

AttrsInfo::AttrsInfo(CPPCompile* _c, const AttributesPtr& _attrs) : CompoundItemInfo(_c) {
    const auto& pas = c->ProcessedAttr();

    for ( const auto& a : _attrs->GetAttrs() ) {
        auto pa = pas.find(a.get());
        ASSERT(pa != pas.end());
        const auto& gi = pa->second;
        init_cohort = max(init_cohort, gi->InitCohort() + 1);
        vals.emplace_back(Fmt(gi->Offset()));
    }
}

GlobalLookupInitInfo::GlobalLookupInitInfo(CPPCompile* c, IDPtr g, string _CPP_name, bool do_init)
    : CPP_InitInfo(g), CPP_name(std::move(_CPP_name)) {
    Zeek_name = g->Name();
    val = ValElem(c, do_init ? g->GetVal() : nullptr);
}

void GlobalLookupInitInfo::InitializerVals(std::vector<std::string>& ivs) const {
    ivs.push_back(CPP_name);
    ivs.push_back(string("\"") + Zeek_name + "\"");
    ivs.push_back(val);
}

GlobalInitInfo::GlobalInitInfo(CPPCompile* c, IDPtr _g, string _CPP_name)
    : GlobalLookupInitInfo(c, _g, std::move(_CPP_name)) {
    g = std::move(_g);
    auto& gt = g->GetType();
    auto gi = c->RegisterType(gt);
    init_cohort = max(init_cohort, gi->FinalInitCohort() + 1);
    type = gi->Offset();

    gi = c->RegisterAttributes(g->GetAttrs());
    if ( gi ) {
        init_cohort = max(init_cohort, gi->FinalInitCohort() + 1);
        attrs = gi->Offset();
    }
    else
        attrs = -1;

    gc.is_exported = g->IsExport();
    gc.is_const = g->IsConst();
    gc.is_option = g->IsOption();
    gc.is_enum_const = g->IsEnumConst();
    gc.is_type = g->IsType();

    // We don't initialize the global directly because its initialization
    // might be an expression rather than a simple constant. Instead we
    // make sure that it can be generated per the use of GetCohortIDs()
    // in CPPCompile::GenFinishInit().
    val = ValElem(c, nullptr);

    // This code here parallels that of CPPCompile::InitializeGlobal().
    const auto& oi = g->GetOptInfo();
    for ( auto& init : oi->GetInitExprs() )
        // We use GetOp2() because initialization expressions are
        // capture in the form of some sort of assignment.
        init_cohort = max(init_cohort, c->ReadyExpr(init->GetOp2()) + 1);

    if ( gt->Tag() == TYPE_FUNC && (! g->GetVal() || g->GetVal()->AsFunc()->GetKind() == Func::BUILTIN_FUNC) )
        // Be sure not to try to create BiFs. In addition, GetVal() can be
        // nil in certain error situations, which we'll want to recreate
        // for behavior compatibility.
        func_with_no_val = true;
}

void GlobalInitInfo::InitializerVals(std::vector<std::string>& ivs) const {
    ivs.push_back(CPP_name);
    ivs.push_back(string("\"") + Zeek_name + "\"");
    ivs.push_back(Fmt(type));
    ivs.push_back(Fmt(attrs));
    ivs.push_back(val);
    ivs.push_back(Fmt(gc.is_exported));
    ivs.push_back(Fmt(gc.is_const));
    ivs.push_back(Fmt(gc.is_option));
    ivs.push_back(Fmt(gc.is_enum_const));
    ivs.push_back(Fmt(gc.is_type));
    ivs.push_back(Fmt(func_with_no_val));
}

CallExprInitInfo::CallExprInitInfo(CPPCompile* c, ExprPtr _e, string _e_name, string _wrapper_class)
    : CPP_InitInfo(_e), e(std::move(_e)), e_name(std::move(_e_name)), wrapper_class(std::move(_wrapper_class)) {
    auto gi = c->RegisterType(e->GetType());
    if ( gi )
        init_cohort = max(init_cohort, gi->InitCohort() + 1);
}

LambdaRegistrationInfo::LambdaRegistrationInfo(CPPCompile* c, string _name, FuncTypePtr ft, string _wrapper_class,
                                               p_hash_type _h, bool _has_captures)
    : CPP_InitInfo(ft),
      name(std::move(_name)),
      wrapper_class(std::move(_wrapper_class)),
      h(_h),
      has_captures(_has_captures) {
    auto gi = c->RegisterType(ft);
    init_cohort = max(init_cohort, gi->InitCohort() + 1);
    func_type = gi->Offset();
}

void LambdaRegistrationInfo::InitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(string("\"") + name + "\"");
    ivs.emplace_back(Fmt(func_type));
    ivs.emplace_back(Fmt(h));
    ivs.emplace_back(has_captures ? "true" : "false");
}

void EnumTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(Fmt(c->TrackString(t->GetName())));

    auto et = t->AsEnumType();

    for ( const auto& name_pair : et->Names() ) {
        ivs.emplace_back(Fmt(c->TrackString(name_pair.first)));
        ivs.emplace_back(Fmt(int(name_pair.second)));
    }
}

void OpaqueTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(Fmt(c->TrackString(t->AsOpaqueType()->Name())));
}

TypeTypeInfo::TypeTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) {
    tt = t->AsTypeType()->GetType();
    auto gi = c->RegisterType(tt);
    if ( gi )
        init_cohort = gi->InitCohort();
}

void TypeTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(to_string(c->TypeOffset(tt)));
}

VectorTypeInfo::VectorTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) {
    auto vt = t->AsVectorType();
    if ( vt->IsUnspecifiedVector() )
        yield = base_type(TYPE_VOID);
    else
        yield = t->Yield();
    auto gi = c->RegisterType(yield);
    if ( gi )
        init_cohort = gi->InitCohort();
}

void VectorTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(to_string(c->TypeOffset(yield)));
}

ListTypeInfo::ListTypeInfo(CPPCompile* _c, TypePtr _t)
    : AbstractTypeInfo(_c, std::move(_t)), types(t->AsTypeList()->GetTypes()) {
    // Note, we leave init_cohort at 0 because the skeleton of this type
    // is built in the first cohort.
    for ( auto& tl_i : types ) {
        auto gi = c->RegisterType(tl_i);
        if ( gi )
            final_init_cohort = max(final_init_cohort, gi->InitCohort());
    }

    if ( ! types.empty() )
        ++final_init_cohort;
}

void ListTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    for ( auto& t : types ) {
        auto iv = Fmt(c->TypeOffset(t));
        ivs.emplace_back(iv);
    }
}

TableTypeInfo::TableTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) {
    // Note, we leave init_cohort at 0 because the skeleton of this type
    // is built in the first cohort.

    auto tbl = t->AsTableType();

    auto gi = c->RegisterType(tbl->GetIndices());
    ASSERT(gi);
    indices = gi->Offset();
    final_init_cohort = gi->InitCohort() + 1;

    yield = tbl->Yield();

    if ( yield ) {
        gi = c->RegisterType(yield);
        if ( gi )
            final_init_cohort = max(final_init_cohort, gi->InitCohort());
    }
}

void TableTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(Fmt(indices));
    ivs.emplace_back(Fmt(yield ? c->TypeOffset(yield) : -1));
}

FuncTypeInfo::FuncTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) {
    auto f = t->AsFuncType();

    flavor = f->Flavor();
    params = f->Params();
    yield = f->Yield();
    expressionless_return_okay = f->ExpressionlessReturnOkay();

    auto gi = c->RegisterType(params);
    if ( gi )
        init_cohort = gi->InitCohort();

    if ( yield ) {
        auto gi = c->RegisterType(f->Yield());
        if ( gi )
            init_cohort = max(init_cohort, gi->InitCohort());
    }
}

void FuncTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(Fmt(c->TypeOffset(params)));
    ivs.emplace_back(Fmt(yield ? c->TypeOffset(yield) : -1));
    ivs.emplace_back(Fmt(static_cast<int>(flavor)));
    ivs.emplace_back(Fmt(static_cast<int>(expressionless_return_okay)));
}

RecordTypeInfo::RecordTypeInfo(CPPCompile* _c, TypePtr _t, int _addl_fields)
    : AbstractTypeInfo(_c, std::move(_t)), addl_fields(_addl_fields) {
    // Note, we leave init_cohort at 0 because the skeleton of this type
    // is built in the first cohort.
    auto r = t->AsRecordType()->Types();

    if ( ! r )
        return;

    for ( const auto& r_i : *r ) {
        field_names.emplace_back(r_i->id);

        auto gi = c->RegisterType(r_i->type);
        if ( gi )
            final_init_cohort = max(final_init_cohort, gi->InitCohort());
        // else it's a recursive type, no need to adjust cohort here

        field_types.push_back(r_i->type);

        if ( r_i->attrs && c->TargetingStandalone() && obj_matches_opt_files(r_i->attrs) == AnalyzeDecision::SHOULD ) {
            gi = c->RegisterAttributes(r_i->attrs);
            final_init_cohort = max(final_init_cohort, gi->InitCohort() + 1);
            field_attrs.push_back(gi->Offset());
        }
        else
            field_attrs.push_back(-1);
    }
}

void RecordTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(Fmt(c->TrackString(t->GetName())));
    ivs.emplace_back(Fmt(addl_fields));

    auto n = field_names.size();

    for ( auto i = 0U; i < n; ++i ) {
        ivs.emplace_back(Fmt(c->TrackString(field_names[i])));

        // Because RecordType's can be recursively defined,
        // during construction we couldn't reliably access
        // the field type's offsets.  At this point, though,
        // they should all be available.
        ivs.emplace_back(Fmt(c->TypeOffset(field_types[i])));
        ivs.emplace_back(Fmt(field_attrs[i]));
    }
}

NamedTypeInfo::NamedTypeInfo(CPPCompile* _c, TypePtr _t) : AbstractTypeInfo(_c, std::move(_t)) {}

void NamedTypeInfo::AddInitializerVals(std::vector<std::string>& ivs) const {
    ivs.emplace_back(Fmt(NAMED_TYPE_MARKER));
    ivs.emplace_back(Fmt(c->TrackString(t->GetName())));
}

void IndicesManager::Generate(CPPCompile* c) {
    c->Emit("int CPP__Indices__init[] =");
    c->StartBlock();

    int nset = 0;
    for ( auto& is : indices_set ) {
        // Track the offsets into the raw vector, to make it
        // easier to debug problems.
        auto line = string("/* ") + to_string(nset++) + " */ ";

        // We first record the size, then the values.
        line += to_string(is.size()) + ", ";

        auto n = 1;
        for ( auto i : is ) {
            line += to_string(i) + ", ";
            if ( ++n % 10 == 0 ) {
                c->Emit(line);
                line.clear();
            }
        }

        if ( ! line.empty() )
            c->Emit(line);
    }

    static const auto end_of_vv = Fmt(END_OF_VEC_VEC);
    c->Emit(end_of_vv);
    c->EndBlock(true);
}

} // namespace zeek::detail
