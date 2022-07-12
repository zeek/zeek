// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

bool CPPCompile::IsNativeType(const TypePtr& t) const
	{
	if ( ! t )
		return true;

	switch ( t->Tag() )
		{
		case TYPE_BOOL:
		case TYPE_COUNT:
		case TYPE_DOUBLE:
		case TYPE_ENUM:
		case TYPE_INT:
		case TYPE_INTERVAL:
		case TYPE_PORT:
		case TYPE_TIME:
		case TYPE_VOID:
			return true;

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
			return false;

		case TYPE_LIST:
			// These occur when initializing tables.
			return false;

		default:
			reporter->InternalError("bad type in CPPCompile::IsNativeType");
			return false;
		}
	}

string CPPCompile::NativeToGT(const string& expr, const TypePtr& t, GenType gt)
	{
	if ( gt == GEN_DONT_CARE )
		return expr;

	if ( gt == GEN_NATIVE || ! IsNativeType(t) )
		return expr;

	// Need to convert to a ValPtr.
	switch ( t->Tag() )
		{
		case TYPE_VOID:
			return expr;

		case TYPE_BOOL:
			return string("val_mgr->Bool(") + expr + ")";

		case TYPE_INT:
			return string("val_mgr->Int(") + expr + ")";

		case TYPE_COUNT:
			return string("val_mgr->Count(") + expr + ")";

		case TYPE_PORT:
			return string("val_mgr->Port(") + expr + ")";

		case TYPE_ENUM:
			return string("make_enum__CPP(") + GenTypeName(t) + ", " + expr + ")";

		default:
			return string("make_intrusive<") + IntrusiveVal(t) + ">(" + expr + ")";
		}
	}

string CPPCompile::GenericValPtrToGT(const string& expr, const TypePtr& t, GenType gt)
	{
	if ( gt != GEN_VAL_PTR && IsNativeType(t) )
		return expr + NativeAccessor(t);
	else
		return string("cast_intrusive<") + IntrusiveVal(t) + ">(" + expr + ")";
	}

string CPPCompile::GenTypeName(const Type* t)
	{
	ASSERT(processed_types.count(TypeRep(t)) > 0);
	return types.KeyName(TypeRep(t));
	}

const char* CPPCompile::TypeTagName(TypeTag tag)
	{
	switch ( tag )
		{
		case TYPE_ADDR:
			return "TYPE_ADDR";
		case TYPE_ANY:
			return "TYPE_ANY";
		case TYPE_BOOL:
			return "TYPE_BOOL";
		case TYPE_COUNT:
			return "TYPE_COUNT";
		case TYPE_DOUBLE:
			return "TYPE_DOUBLE";
		case TYPE_ENUM:
			return "TYPE_ENUM";
		case TYPE_ERROR:
			return "TYPE_ERROR";
		case TYPE_FILE:
			return "TYPE_FILE";
		case TYPE_FUNC:
			return "TYPE_FUNC";
		case TYPE_INT:
			return "TYPE_INT";
		case TYPE_INTERVAL:
			return "TYPE_INTERVAL";
		case TYPE_LIST:
			return "TYPE_LIST";
		case TYPE_OPAQUE:
			return "TYPE_OPAQUE";
		case TYPE_PATTERN:
			return "TYPE_PATTERN";
		case TYPE_PORT:
			return "TYPE_PORT";
		case TYPE_RECORD:
			return "TYPE_RECORD";
		case TYPE_STRING:
			return "TYPE_STRING";
		case TYPE_SUBNET:
			return "TYPE_SUBNET";
		case TYPE_TABLE:
			return "TYPE_TABLE";
		case TYPE_TIME:
			return "TYPE_TIME";
		case TYPE_TYPE:
			return "TYPE_TYPE";
		case TYPE_VECTOR:
			return "TYPE_VECTOR";
		case TYPE_VOID:
			return "TYPE_VOID";

		default:
			reporter->InternalError("bad type in CPPCompile::TypeTagName");
			return nullptr;
		}
	}

const char* CPPCompile::TypeName(const TypePtr& t)
	{
	switch ( t->Tag() )
		{
		case TYPE_BOOL:
			return "bool";
		case TYPE_COUNT:
			return "zeek_uint_t";
		case TYPE_DOUBLE:
			return "double";
		case TYPE_ENUM:
			return "int";
		case TYPE_INT:
			return "zeek_int_t";
		case TYPE_INTERVAL:
			return "double";
		case TYPE_PORT:
			return "zeek_uint_t";
		case TYPE_TIME:
			return "double";
		case TYPE_VOID:
			return "void";

		case TYPE_ADDR:
			return "AddrVal";
		case TYPE_ANY:
			return "Val";
		case TYPE_FILE:
			return "FileVal";
		case TYPE_FUNC:
			return "FuncVal";
		case TYPE_OPAQUE:
			return "OpaqueVal";
		case TYPE_PATTERN:
			return "PatternVal";
		case TYPE_RECORD:
			return "RecordVal";
		case TYPE_STRING:
			return "StringVal";
		case TYPE_SUBNET:
			return "SubNetVal";
		case TYPE_TABLE:
			return "TableVal";
		case TYPE_TYPE:
			return "TypeVal";
		case TYPE_VECTOR:
			return "VectorVal";

		default:
			reporter->InternalError("bad type in CPPCompile::TypeName");
			return nullptr;
		}
	}

const char* CPPCompile::FullTypeName(const TypePtr& t)
	{
	if ( ! t )
		return "void";

	switch ( t->Tag() )
		{
		case TYPE_BOOL:
		case TYPE_COUNT:
		case TYPE_DOUBLE:
		case TYPE_ENUM:
		case TYPE_INT:
		case TYPE_INTERVAL:
		case TYPE_PORT:
		case TYPE_TIME:
		case TYPE_VOID:
			return TypeName(t);

		case TYPE_ADDR:
			return "AddrValPtr";
		case TYPE_ANY:
			return "ValPtr";
		case TYPE_FILE:
			return "FileValPtr";
		case TYPE_FUNC:
			return "FuncValPtr";
		case TYPE_OPAQUE:
			return "OpaqueValPtr";
		case TYPE_PATTERN:
			return "PatternValPtr";
		case TYPE_RECORD:
			return "RecordValPtr";
		case TYPE_STRING:
			return "StringValPtr";
		case TYPE_SUBNET:
			return "SubNetValPtr";
		case TYPE_TABLE:
			return "TableValPtr";
		case TYPE_TYPE:
			return "TypeValPtr";
		case TYPE_VECTOR:
			return "VectorValPtr";

		default:
			reporter->InternalError("bad type in CPPCompile::FullTypeName");
			return nullptr;
		}
	}

const char* CPPCompile::TypeType(const TypePtr& t)
	{
	switch ( t->Tag() )
		{
		case TYPE_RECORD:
			return "RecordType";
		case TYPE_TABLE:
			return "TableType";
		case TYPE_VECTOR:
			return "VectorType";

		default:
			reporter->InternalError("bad type in CPPCompile::TypeType");
			return nullptr;
		}
	}

shared_ptr<CPP_InitInfo> CPPCompile::RegisterType(const TypePtr& tp)
	{
	auto t = TypeRep(tp);

	auto pt = processed_types.find(t);
	if ( pt != processed_types.end() )
		return pt->second;

	processed_types[t] = nullptr;

	shared_ptr<CPP_InitInfo> gi;

	switch ( t->Tag() )
		{
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
		case TYPE_FILE:
			gi = make_shared<BaseTypeInfo>(this, tp);
			break;

		case TYPE_ENUM:
			gi = make_shared<EnumTypeInfo>(this, tp);
			break;

		case TYPE_OPAQUE:
			gi = make_shared<OpaqueTypeInfo>(this, tp);
			break;

		case TYPE_TYPE:
			gi = make_shared<TypeTypeInfo>(this, tp);
			break;

		case TYPE_VECTOR:
			gi = make_shared<VectorTypeInfo>(this, tp);
			break;

		case TYPE_LIST:
			gi = make_shared<ListTypeInfo>(this, tp);
			break;

		case TYPE_TABLE:
			gi = make_shared<TableTypeInfo>(this, tp);
			break;

		case TYPE_RECORD:
			gi = make_shared<RecordTypeInfo>(this, tp);
			break;

		case TYPE_FUNC:
			gi = make_shared<FuncTypeInfo>(this, tp);
			break;

		default:
			reporter->InternalError("bad type in CPPCompile::RegisterType");
		}

	type_info->AddInstance(gi);
	processed_types[t] = gi;

	types.AddInitInfo(t, gi);

	return gi;
	}

const char* CPPCompile::NativeAccessor(const TypePtr& t)
	{
	switch ( t->Tag() )
		{
		case TYPE_BOOL:
			return "->AsBool()";
		case TYPE_COUNT:
			return "->AsCount()";
		case TYPE_DOUBLE:
			return "->AsDouble()";
		case TYPE_ENUM:
			return "->AsEnum()";
		case TYPE_INT:
			return "->AsInt()";
		case TYPE_INTERVAL:
			return "->AsDouble()";
		case TYPE_PORT:
			return "->AsCount()";
		case TYPE_TIME:
			return "->AsDouble()";

		case TYPE_ADDR:
			return "->AsAddrVal()";
		case TYPE_FILE:
			return "->AsFileVal()";
		case TYPE_FUNC:
			return "->AsFuncVal()";
		case TYPE_OPAQUE:
			return "->AsOpaqueVal()";
		case TYPE_PATTERN:
			return "->AsPatternVal()";
		case TYPE_RECORD:
			return "->AsRecordVal()";
		case TYPE_STRING:
			return "->AsStringVal()";
		case TYPE_SUBNET:
			return "->AsSubNetVal()";
		case TYPE_TABLE:
			return "->AsTableVal()";
		case TYPE_TYPE:
			return "->AsTypeVal()";
		case TYPE_VECTOR:
			return "->AsVectorVal()";

		case TYPE_ANY:
			return ".get()";

		case TYPE_VOID:
			return "";

		default:
			reporter->InternalError("bad type in CPPCompile::NativeAccessor");
			return nullptr;
		}
	}

const char* CPPCompile::IntrusiveVal(const TypePtr& t)
	{
	switch ( t->Tag() )
		{
		case TYPE_BOOL:
			return "BoolVal";
		case TYPE_COUNT:
			return "CountVal";
		case TYPE_DOUBLE:
			return "DoubleVal";
		case TYPE_ENUM:
			return "EnumVal";
		case TYPE_INT:
			return "IntVal";
		case TYPE_INTERVAL:
			return "IntervalVal";
		case TYPE_PORT:
			return "PortVal";
		case TYPE_TIME:
			return "TimeVal";

		case TYPE_ADDR:
			return "AddrVal";
		case TYPE_ANY:
			return "Val";
		case TYPE_FILE:
			return "FileVal";
		case TYPE_FUNC:
			return "FuncVal";
		case TYPE_OPAQUE:
			return "OpaqueVal";
		case TYPE_PATTERN:
			return "PatternVal";
		case TYPE_RECORD:
			return "RecordVal";
		case TYPE_STRING:
			return "StringVal";
		case TYPE_SUBNET:
			return "SubNetVal";
		case TYPE_TABLE:
			return "TableVal";
		case TYPE_TYPE:
			return "TypeVal";
		case TYPE_VECTOR:
			return "VectorVal";

		default:
			reporter->InternalError("bad type in CPPCompile::IntrusiveVal");
			return nullptr;
		}
	}

	} // zeek::detail
