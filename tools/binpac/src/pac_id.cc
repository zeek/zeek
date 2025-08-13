// See the file "COPYING" in the main distribution directory for copyright.

#include "pac_id.h"

#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_field.h"
#include "pac_type.h"
#include "pac_utils.h"

const ID* default_value_var = nullptr;
const ID* null_id = nullptr;
const ID* null_byteseg_id = nullptr;
const ID* null_decl_id = nullptr;
const ID* begin_of_data = nullptr;
const ID* end_of_data = nullptr;
const ID* len_of_data = nullptr;
const ID* byteorder_id = nullptr;
const ID* bigendian_id = nullptr;
const ID* littleendian_id = nullptr;
const ID* unspecified_byteorder_id = nullptr;
const ID* const_true_id = nullptr;
const ID* const_false_id = nullptr;
const ID* analyzer_context_id = nullptr;
const ID* context_macro_id = nullptr;
const ID* this_id = nullptr;
const ID* sourcedata_id = nullptr;
const ID* connection_id = nullptr;
const ID* upflow_id = nullptr;
const ID* downflow_id = nullptr;
const ID* dataunit_id = nullptr;
const ID* flow_buffer_id = nullptr;
const ID* element_macro_id = nullptr;
const ID* input_macro_id = nullptr;
const ID* cxt_connection_id = nullptr;
const ID* cxt_flow_id = nullptr;
const ID* parsing_state_id = nullptr;
const ID* buffering_state_id = nullptr;

int ID::anonymous_id_seq = 0;

ID* ID::NewAnonymousID(const string& prefix) {
    ID* id = new ID(strfmt("%s%03d", prefix.c_str(), ++anonymous_id_seq));
    id->anonymous_id_ = true;
    return id;
}

IDRecord::IDRecord(Env* arg_env, const ID* arg_id, IDType arg_id_type)
    : env(arg_env), id(arg_id), id_type(arg_id_type) {
    eval = nullptr;
    evaluated = in_evaluation = false;
    setfunc = ""; // except for STATE_VAR
    switch ( id_type ) {
        case MEMBER_VAR:
            rvalue = strfmt("%s()", id->Name());
            lvalue = strfmt("%s_", id->Name());
            break;
        case PRIV_MEMBER_VAR:
            rvalue = strfmt("%s_", id->Name());
            lvalue = strfmt("%s_", id->Name());
            break;
        case UNION_VAR:
            rvalue = strfmt("%s()", id->Name());
            lvalue = strfmt("%s_", id->Name());
            break;
        case CONST:
        case GLOBAL_VAR:
            rvalue = strfmt("%s", id->Name());
            lvalue = strfmt("%s", id->Name());
            break;
        case TEMP_VAR:
            rvalue = strfmt("t_%s", id->Name());
            lvalue = strfmt("t_%s", id->Name());
            break;
        case STATE_VAR:
            rvalue = strfmt("%s()", id->Name());
            lvalue = strfmt("%s_", id->Name());
            break;
        case MACRO:
            rvalue = "@MACRO@";
            lvalue = "@MACRO@";
            break;
        case FUNC_ID:
            rvalue = strfmt("%s", id->Name());
            lvalue = "@FUNC_ID@";
            break;
        case FUNC_PARAM:
            rvalue = strfmt("%s", id->Name());
            lvalue = "@FUNC_PARAM@";
            break;
    }

    data_type = nullptr;
    field = nullptr;
    constant = constant_set = false;
    macro = nullptr;
}

IDRecord::~IDRecord() {}

void IDRecord::SetConstant(int c) {
    ASSERT(id_type == CONST);
    constant_set = true;
    constant = c;
}

bool IDRecord::GetConstant(int* pc) const {
    if ( constant_set )
        *pc = constant;
    return constant_set;
}

void IDRecord::SetMacro(Expr* e) {
    ASSERT(id_type == MACRO);
    macro = e;
}

Expr* IDRecord::GetMacro() const {
    ASSERT(id_type == MACRO);
    return macro;
}

void IDRecord::SetEvaluated(bool v) {
    if ( v )
        ASSERT(! evaluated);
    evaluated = v;
}

void IDRecord::Evaluate(Output* out, Env* env) {
    if ( evaluated )
        return;

    if ( ! out )
        throw ExceptionIDNotEvaluated(id);

    if ( ! eval )
        throw Exception(id, "no evaluation method");

    if ( in_evaluation )
        throw ExceptionCyclicDependence(id);

    in_evaluation = true;
    eval->GenEval(out, env);
    in_evaluation = false;

    evaluated = true;
}

const char* IDRecord::RValue() const {
    if ( id_type == MACRO )
        return macro->EvalExpr(nullptr, env);

    if ( id_type == TEMP_VAR && ! evaluated )
        throw ExceptionIDNotEvaluated(id);

    return rvalue.c_str();
}

const char* IDRecord::LValue() const {
    ASSERT(id_type != MACRO && id_type != FUNC_ID);
    return lvalue.c_str();
}

Env::Env(Env* parent_env, Object* context_object) : parent(parent_env), context_object_(context_object) {
    allow_undefined_id_ = false;
    in_branch_ = false;
}

Env::~Env() {
    for ( id_map_t::iterator it = id_map.begin(); it != id_map.end(); ++it ) {
        delete it->second;
        it->second = 0;
    }
}

void Env::AddID(const ID* id, IDType id_type, Type* data_type) {
    DEBUG_MSG("To add ID `%s'...\n", id->Name());
    id_map_t::iterator it = id_map.find(id);
    if ( it != id_map.end() ) {
        DEBUG_MSG("Duplicate definition: `%s'\n", it->first->Name());
        throw ExceptionIDRedefinition(id);
    }
    id_map[id] = new IDRecord(this, id, id_type);
    // TODO: figure out when data_type must be non-NULL
    // ASSERT(data_type);
    SetDataType(id, data_type);
}

void Env::AddConstID(const ID* id, const int c, Type* type) {
    if ( ! type )
        type = extern_type_int;
    AddID(id, CONST, type);
    SetConstant(id, c);
    SetEvaluated(id); // a constant is always evaluated
}

void Env::AddMacro(const ID* id, Expr* macro) {
    AddID(id, MACRO, macro->DataType(this));
    SetMacro(id, macro);
    SetEvaluated(id);
}

ID* Env::AddTempID(Type* type) {
    ID* id = ID::NewAnonymousID("t_var_");
    AddID(id, TEMP_VAR, type);
    return id;
}

IDRecord* Env::lookup(const ID* id, bool recursive, bool raise_exception) const {
    ASSERT(id);

    id_map_t::const_iterator it = id_map.find(id);
    if ( it != id_map.end() )
        return it->second;

    if ( recursive && parent )
        return parent->lookup(id, recursive, raise_exception);

    if ( raise_exception )
        throw ExceptionIDNotFound(id);
    else
        return nullptr;
}

IDType Env::GetIDType(const ID* id) const { return lookup(id, true, true)->GetType(); }

const char* Env::RValue(const ID* id) const {
    IDRecord* r = lookup(id, true, false);
    if ( r )
        return r->RValue();
    else {
        if ( allow_undefined_id() )
            return id->Name();
        else
            throw ExceptionIDNotFound(id);
    }
}

const char* Env::LValue(const ID* id) const { return lookup(id, true, true)->LValue(); }

void Env::SetEvalMethod(const ID* id, Evaluatable* eval) { lookup(id, true, true)->SetEvalMethod(eval); }

void Env::Evaluate(Output* out, const ID* id) {
    IDRecord* r = lookup(id, true, ! allow_undefined_id());
    if ( r )
        r->Evaluate(out, this);
}

bool Env::Evaluated(const ID* id) const {
    IDRecord* r = lookup(id, true, ! allow_undefined_id());
    if ( r )
        return r->Evaluated();
    else
        // Assume undefined variables are already evaluated
        return true;
}

void Env::SetEvaluated(const ID* id, bool v) {
    if ( in_branch() ) {
        Field* f = GetField(id);
        if ( f && f->tof() == LET_FIELD ) {
            throw Exception(context_object_, strfmt("INTERNAL ERROR: "
                                                    "evaluating let field '%s' in a branch! "
                                                    "To work around this problem, "
                                                    "add '&requires(%s)' to the case type. "
                                                    "Sorry for the inconvenience.\n",
                                                    id->Name(), id->Name()));
            ASSERT(0);
        }
    }

    IDRecord* r = lookup(id, false, false);
    if ( r )
        r->SetEvaluated(v);
    else if ( parent )
        parent->SetEvaluated(id, v);
    else
        throw ExceptionIDNotFound(id);
}

void Env::SetField(const ID* id, Field* field) { lookup(id, false, true)->SetField(field); }

Field* Env::GetField(const ID* id) const { return lookup(id, true, true)->GetField(); }

void Env::SetDataType(const ID* id, Type* type) { lookup(id, true, true)->SetDataType(type); }

Type* Env::GetDataType(const ID* id) const {
    IDRecord* r = lookup(id, true, false);
    if ( r )
        return r->GetDataType();
    else
        return nullptr;
}

string Env::DataTypeStr(const ID* id) const {
    Type* type = GetDataType(id);
    if ( ! type )
        throw Exception(id, "data type not defined");
    return type->DataTypeStr();
}

void Env::SetConstant(const ID* id, int constant) { lookup(id, false, true)->SetConstant(constant); }

bool Env::GetConstant(const ID* id, int* pc) const {
    ASSERT(pc);
    // lookup without raising exception
    IDRecord* r = lookup(id, true, false);
    if ( r )
        return r->GetConstant(pc);
    else
        return false;
}

void Env::SetMacro(const ID* id, Expr* macro) { lookup(id, true, true)->SetMacro(macro); }

Expr* Env::GetMacro(const ID* id) const { return lookup(id, true, true)->GetMacro(); }

void init_builtin_identifiers() {
    default_value_var = new ID("val");
    null_id = new ID("NULL");
    null_byteseg_id = new ID("null_byteseg");
    begin_of_data = new ID("begin_of_data");
    end_of_data = new ID("end_of_data");
    len_of_data = new ID("length_of_data");
    byteorder_id = new ID("byteorder");
    bigendian_id = new ID("bigendian");
    littleendian_id = new ID("littleendian");
    unspecified_byteorder_id = new ID("unspecified_byteorder");
    const_true_id = new ID("true");
    const_false_id = new ID("false");
    analyzer_context_id = new ID("context");
    this_id = new ID("this");
    sourcedata_id = new ID("sourcedata");
    connection_id = new ID("connection");
    upflow_id = new ID("upflow");
    downflow_id = new ID("downflow");
    dataunit_id = new ID("dataunit");
    flow_buffer_id = new ID("flow_buffer");
    element_macro_id = new ID("$element");
    input_macro_id = new ID("$input");
    context_macro_id = new ID("$context");
    parsing_state_id = new ID("parsing_state");
    buffering_state_id = new ID("buffering_state");

    null_decl_id = new ID("<null-decl>");
    current_decl_id = null_decl_id;
}

Env* global_env() {
    static Env* the_global_env = nullptr;

    if ( ! the_global_env ) {
        the_global_env = new Env(nullptr, nullptr);

        // These two are defined in binpac.h, so we do not need to
        // generate code for them.
        the_global_env->AddConstID(bigendian_id, 0);
        the_global_env->AddConstID(littleendian_id, 1);
        the_global_env->AddConstID(unspecified_byteorder_id, -1);
        the_global_env->AddConstID(const_false_id, 0);
        the_global_env->AddConstID(const_true_id, 1);
        // A hack for ID "this"
        the_global_env->AddConstID(this_id, 0);
        the_global_env->AddConstID(null_id, 0, extern_type_nullptr);

#if 0
		the_global_env->AddID(null_byteseg_id,
			GLOBAL_VAR,
			extern_type_const_byteseg);
#endif
    }

    return the_global_env;
}

string set_function(const ID* id) { return strfmt("set_%s", id->Name()); }
