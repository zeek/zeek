#include "pac_exttype.h"

#include "pac_decl.h"
#include "pac_id.h"
#include "pac_output.h"

bool ExternType::DefineValueVar() const { return true; }

string ExternType::DataTypeStr() const {
    switch ( ext_type_ ) {
        case PLAIN:
        case NUMBER:
        case BOOLEAN: return id_->Name();
        case POINTER: return string(id_->Name()) + " *";
        default: ASSERT(0); return "";
    }
}

int ExternType::StaticSize(Env* env) const {
    ASSERT(0);
    return -1;
}

bool ExternType::ByteOrderSensitive() const { return false; }

string ExternType::EvalMember(const ID* member_id) const {
    return strfmt("%s%s", ext_type_ == POINTER ? "->" : ".", member_id->Name());
}

void ExternType::GenInitCode(Output* out_cc, Env* env) {
    if ( IsNumericType() )
        out_cc->println("%s = 0;", env->LValue(value_var()));
    else if ( IsPointerType() )
        out_cc->println("%s = nullptr;", env->LValue(value_var()));
    else if ( IsBooleanType() )
        out_cc->println("%s = false;", env->LValue(value_var()));

    Type::GenInitCode(out_cc, env);
}

void ExternType::DoGenParseCode(Output* out, Env* env, const DataPtr& data, int flags) { ASSERT(0); }

void ExternType::GenDynamicSize(Output* out, Env* env, const DataPtr& data) { ASSERT(0); }

Type* ExternType::DoClone() const { return new ExternType(id_->clone(), ext_type_); }

// Definitions of pre-defined external types

#define EXTERNTYPE(name, ctype, exttype) ExternType* extern_type_##name = 0;
#include "pac_externtype.def"
#undef EXTERNTYPE

void ExternType::static_init() {
    ID* id;
    // TypeDecl *decl;
    // decl = new TypeDecl(id, 0, extern_type_##name);

#define EXTERNTYPE(name, ctype, exttype)                                                                               \
    id = new ID(#ctype);                                                                                               \
    extern_type_##name = new ExternType(id, ExternType::exttype);                                                      \
    Type::AddPredefinedType(#name, extern_type_##name);
#include "pac_externtype.def"
#undef EXTERNTYPE
}
