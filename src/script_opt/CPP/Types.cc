// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail {

using namespace std;

bool CPPCompile::IsNativeType(const TypePtr& t) const {
    if ( ! t )
        return true;

    switch ( t->Tag() ) {
        case TYPE_BOOL:
        case TYPE_COUNT:
        case TYPE_DOUBLE:
        case TYPE_ENUM:
        case TYPE_INT:
        case TYPE_INTERVAL:
        case TYPE_PORT:
        case TYPE_TIME:
        case TYPE_VOID: return true;

        case TYPE_ADDR:
        case TYPE_ANY:
        case TYPE_FILE:
        case TYPE_FUNC:
        case TYPE_OPAQUE:
        case TYPE_PATTERN:
        case TYPE_RECORD:
        case TYPE_STRING:
        case TYPE_SUBNET:
        case TYPE_TABLE:
        case TYPE_TYPE:
        case TYPE_VECTOR:
        // These occur when initializing tables.
        case TYPE_LIST: return false;

        default: reporter->InternalError("bad type in CPPCompile::IsNativeType"); return false;
    }
}

string CPPCompile::NativeToGT(const string& expr, const TypePtr& t, GenType gt) {
    if ( gt == GEN_DONT_CARE )
        return expr;

    if ( gt == GEN_NATIVE || ! IsNativeType(t) )
        return expr;

    // Need to convert to a ValPtr.
    switch ( t->Tag() ) {
        case TYPE_VOID: return expr;

        case TYPE_BOOL: return string("val_mgr->Bool(") + expr + ")";

        case TYPE_INT: return string("val_mgr->Int(") + expr + ")";

        case TYPE_COUNT: return string("val_mgr->Count(") + expr + ")";

        case TYPE_PORT: return string("val_mgr->Port(") + expr + ")";

        case TYPE_ENUM: return string("make_enum__CPP(") + GenTypeName(t) + ", " + expr + ")";

        default: return string("make_intrusive<") + IntrusiveVal(t) + ">(" + expr + ")";
    }
}

string CPPCompile::GenericValPtrToGT(const string& expr, const TypePtr& t, GenType gt) {
    if ( gt != GEN_VAL_PTR && IsNativeType(t) )
        return expr + NativeAccessor(t);
    else
        return string("cast_intrusive<") + IntrusiveVal(t) + ">(" + expr + ")";
}

string CPPCompile::GenTypeName(const Type* t) {
    ASSERT(processed_types.contains(TypeRep(t)));
    return types.KeyName(TypeRep(t));
}

const char* CPPCompile::TypeTagName(TypeTag tag) {
    switch ( tag ) {
        case TYPE_ADDR: return "TYPE_ADDR";
        case TYPE_ANY: return "TYPE_ANY";
        case TYPE_BOOL: return "TYPE_BOOL";
        case TYPE_COUNT: return "TYPE_COUNT";
        case TYPE_DOUBLE: return "TYPE_DOUBLE";
        case TYPE_ENUM: return "TYPE_ENUM";
        case TYPE_ERROR: return "TYPE_ERROR";
        case TYPE_FILE: return "TYPE_FILE";
        case TYPE_FUNC: return "TYPE_FUNC";
        case TYPE_INT: return "TYPE_INT";
        case TYPE_INTERVAL: return "TYPE_INTERVAL";
        case TYPE_LIST: return "TYPE_LIST";
        case TYPE_OPAQUE: return "TYPE_OPAQUE";
        case TYPE_PATTERN: return "TYPE_PATTERN";
        case TYPE_PORT: return "TYPE_PORT";
        case TYPE_RECORD: return "TYPE_RECORD";
        case TYPE_STRING: return "TYPE_STRING";
        case TYPE_SUBNET: return "TYPE_SUBNET";
        case TYPE_TABLE: return "TYPE_TABLE";
        case TYPE_TIME: return "TYPE_TIME";
        case TYPE_TYPE: return "TYPE_TYPE";
        case TYPE_VECTOR: return "TYPE_VECTOR";
        case TYPE_VOID: return "TYPE_VOID";

        default: reporter->InternalError("bad type in CPPCompile::TypeTagName"); return nullptr;
    }
}

const char* CPPCompile::TypeName(const TypePtr& t) {
    switch ( t->Tag() ) {
        case TYPE_BOOL: return "bool";
        case TYPE_COUNT: return "zeek_uint_t";
        case TYPE_DOUBLE: return "double";
        case TYPE_ENUM:
        case TYPE_INT: return "zeek_int_t";
        case TYPE_INTERVAL: return "double";
        case TYPE_PORT: return "zeek_uint_t";
        case TYPE_TIME: return "double";
        case TYPE_VOID: return "void";

        case TYPE_ADDR: return "AddrVal";
        case TYPE_ANY: return "Val";
        case TYPE_FILE: return "FileVal";
        case TYPE_FUNC: return "FuncVal";
        case TYPE_OPAQUE: return "OpaqueVal";
        case TYPE_PATTERN: return "PatternVal";
        case TYPE_RECORD: return "RecordVal";
        case TYPE_STRING: return "StringVal";
        case TYPE_SUBNET: return "SubNetVal";
        case TYPE_TABLE: return "TableVal";
        case TYPE_TYPE: return "TypeVal";
        case TYPE_VECTOR: return "VectorVal";

        default: reporter->InternalError("bad type in CPPCompile::TypeName"); return nullptr;
    }
}

const char* CPPCompile::FullTypeName(const TypePtr& t) {
    if ( ! t )
        return "void";

    switch ( t->Tag() ) {
        case TYPE_BOOL:
        case TYPE_COUNT:
        case TYPE_DOUBLE:
        case TYPE_ENUM:
        case TYPE_INT:
        case TYPE_INTERVAL:
        case TYPE_PORT:
        case TYPE_TIME:
        case TYPE_VOID: return TypeName(t);

        case TYPE_ADDR: return "AddrValPtr";
        case TYPE_ANY: return "ValPtr";
        case TYPE_FILE: return "FileValPtr";
        case TYPE_FUNC: return "FuncValPtr";
        case TYPE_OPAQUE: return "OpaqueValPtr";
        case TYPE_PATTERN: return "PatternValPtr";
        case TYPE_RECORD: return "RecordValPtr";
        case TYPE_STRING: return "StringValPtr";
        case TYPE_SUBNET: return "SubNetValPtr";
        case TYPE_TABLE: return "TableValPtr";
        case TYPE_TYPE: return "TypeValPtr";
        case TYPE_VECTOR: return "VectorValPtr";

        default: reporter->InternalError("bad type in CPPCompile::FullTypeName"); return nullptr;
    }
}

const char* CPPCompile::TypeType(const TypePtr& t) {
    switch ( t->Tag() ) {
        case TYPE_RECORD: return "RecordType";
        case TYPE_TABLE: return "TableType";
        case TYPE_VECTOR: return "VectorType";

        default: reporter->InternalError("bad type in CPPCompile::TypeType"); return nullptr;
    }
}

shared_ptr<CPP_InitInfo> CPPCompile::RegisterType(const TypePtr& tp) {
    auto t = TypeRep(tp);

    auto pt = processed_types.find(t);
    if ( pt != processed_types.end() )
        return pt->second;

    processed_types[t] = nullptr;

    // When doing standalone compilation, if the type is a record *and*
    // (1) it's not one that we're fully generating (i.e., it's not solely
    // defined in the scripts that we're compiling-to-standalone), and (2) the
    // scripts we're compiling extend the record using "redef += record ...",
    // then we need to track the offset where those record extensions start,
    // so that when initializing the standalone code, we can add in those
    // record fields.
    //
    // If any of those conditions don't hold, then this variable will remain 0.
    int addl_fields = 0;

    bool type_init_needed = standalone && obj_matches_opt_files(tp);

    if ( standalone && ! type_init_needed ) {
        if ( tp->Tag() == TYPE_RECORD ) {
            auto tr = tp->AsRecordType();
            for ( auto i = tr->NumOrigFields(); i < tr->NumFields(); ++i ) {
                auto fd = tr->FieldDecl(i);
                if ( filename_matches_opt_files(fd->GetLocationInfo()->FileName()) ) {
                    if ( addl_fields == 0 )
                        addl_fields = i;
                }
                else if ( addl_fields > 0 )
                    reporter->FatalError(
                        "can't compile standalone-C++ with field \"%s\" in record \"%s\" added after those introduced "
                        "by compiled script",
                        fd->id, t->GetName().c_str());
            }

            if ( addl_fields > 0 )
                type_init_needed = true;
        }
    }

    shared_ptr<CPP_InitInfo> gi;

    if ( type_init_needed || t->GetName().empty() ) {
        switch ( t->Tag() ) {
            case TYPE_ADDR:
            case TYPE_ANY:
            case TYPE_BOOL:
            case TYPE_COUNT:
            case TYPE_DOUBLE:
            case TYPE_ERROR:
            case TYPE_INT:
            case TYPE_INTERVAL:
            case TYPE_PATTERN:
            case TYPE_PORT:
            case TYPE_STRING:
            case TYPE_TIME:
            case TYPE_VOID:
            case TYPE_SUBNET:
            case TYPE_FILE: gi = make_shared<BaseTypeInfo>(this, tp); break;

            case TYPE_ENUM: gi = make_shared<EnumTypeInfo>(this, tp); break;

            case TYPE_OPAQUE: gi = make_shared<OpaqueTypeInfo>(this, tp); break;

            case TYPE_TYPE: gi = make_shared<TypeTypeInfo>(this, tp); break;

            case TYPE_VECTOR: gi = make_shared<VectorTypeInfo>(this, tp); break;

            case TYPE_LIST: gi = make_shared<ListTypeInfo>(this, tp); break;

            case TYPE_TABLE: gi = make_shared<TableTypeInfo>(this, tp); break;

            case TYPE_RECORD: gi = make_shared<RecordTypeInfo>(this, tp, addl_fields); break;

            case TYPE_FUNC: gi = make_shared<FuncTypeInfo>(this, tp); break;

            default: reporter->InternalError("bad type in CPPCompile::RegisterType");
        }
    }
    else
        gi = make_shared<NamedTypeInfo>(this, tp);

    type_info->AddInstance(gi);
    processed_types[t] = gi;

    types.AddInitInfo(t, gi);

    return gi;
}

const char* CPPCompile::NativeAccessor(const TypePtr& t) {
    switch ( t->Tag() ) {
        case TYPE_BOOL: return "->AsBool()";
        case TYPE_COUNT: return "->AsCount()";
        case TYPE_DOUBLE: return "->AsDouble()";
        case TYPE_ENUM: return "->AsEnum()";
        case TYPE_INT: return "->AsInt()";
        case TYPE_INTERVAL: return "->AsDouble()";
        case TYPE_PORT: return "->AsCount()";
        case TYPE_TIME: return "->AsDouble()";

        case TYPE_ADDR: return "->AsAddrVal()";
        case TYPE_FILE: return "->AsFileVal()";
        case TYPE_FUNC: return "->AsFuncVal()";
        case TYPE_OPAQUE: return "->AsOpaqueVal()";
        case TYPE_PATTERN: return "->AsPatternVal()";
        case TYPE_RECORD: return "->AsRecordVal()";
        case TYPE_STRING: return "->AsStringVal()";
        case TYPE_SUBNET: return "->AsSubNetVal()";
        case TYPE_TABLE: return "->AsTableVal()";
        case TYPE_TYPE: return "->AsTypeVal()";
        case TYPE_VECTOR: return "->AsVectorVal()";

        case TYPE_ANY: return ".get()";

        case TYPE_VOID: return "";

        default: reporter->InternalError("bad type in CPPCompile::NativeAccessor"); return nullptr;
    }
}

const char* CPPCompile::IntrusiveVal(const TypePtr& t) {
    switch ( t->Tag() ) {
        case TYPE_BOOL: return "BoolVal";
        case TYPE_COUNT: return "CountVal";
        case TYPE_DOUBLE: return "DoubleVal";
        case TYPE_ENUM: return "EnumVal";
        case TYPE_INT: return "IntVal";
        case TYPE_INTERVAL: return "IntervalVal";
        case TYPE_PORT: return "PortVal";
        case TYPE_TIME: return "TimeVal";

        case TYPE_ADDR: return "AddrVal";
        case TYPE_ANY: return "Val";
        case TYPE_FILE: return "FileVal";
        case TYPE_FUNC: return "FuncVal";
        case TYPE_OPAQUE: return "OpaqueVal";
        case TYPE_PATTERN: return "PatternVal";
        case TYPE_RECORD: return "RecordVal";
        case TYPE_STRING: return "StringVal";
        case TYPE_SUBNET: return "SubNetVal";
        case TYPE_TABLE: return "TableVal";
        case TYPE_TYPE: return "TypeVal";
        case TYPE_VECTOR: return "VectorVal";

        default: reporter->InternalError("bad type in CPPCompile::IntrusiveVal"); return nullptr;
    }
}

} // namespace zeek::detail
