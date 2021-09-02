// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"


namespace zeek::detail {

using namespace std;

bool CPPCompile::IsNativeType(const TypePtr& t) const
	{
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
	switch ( t->Tag() ) {
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
		return string("make_enum__CPP(") + GenTypeName(t) + ", " +
					expr + ")";

	default:
		return string("make_intrusive<") + IntrusiveVal(t) +
			">(" + expr + ")";
	}
	}

string CPPCompile::GenericValPtrToGT(const string& expr, const TypePtr& t,
                                     GenType gt)
	{
	if ( gt != GEN_VAL_PTR && IsNativeType(t) )
		return expr + NativeAccessor(t);
	else
		return string("cast_intrusive<") + IntrusiveVal(t) +
		       ">(" + expr + ")";
	}

void CPPCompile::ExpandTypeVar(const TypePtr& t)
	{
	auto tn = GenTypeName(t);

	switch ( t->Tag() ) {
	case TYPE_LIST:
		ExpandListTypeVar(t, tn);
		break;

	case TYPE_RECORD:
		ExpandRecordTypeVar(t, tn);
		break;

	case TYPE_ENUM:
		ExpandEnumTypeVar(t, tn);
		break;

	case TYPE_TABLE:
		ExpandTableTypeVar(t, tn);
		break;

	case TYPE_FUNC:
		ExpandFuncTypeVar(t, tn);
		break;

	case TYPE_TYPE:
		AddInit(t, tn, string("make_intrusive<TypeType>(") +
		        GenTypeName(t->AsTypeType()->GetType()) + ")");
		break;

	case TYPE_VECTOR:
		AddInit(t, tn, string("make_intrusive<VectorType>(") +
		        GenTypeName(t->AsVectorType()->Yield()) + ")");
		break;

	default:
		break;
	}

	auto& script_type_name = t->GetName();
	if ( ! script_type_name.empty() )
		AddInit(t, "register_type__CPP(" + tn + ", \"" +
		           script_type_name + "\");");

	AddInit(t);
	}

void CPPCompile::ExpandListTypeVar(const TypePtr& t, string& tn)
	{
	const auto& tl = t->AsTypeList()->GetTypes();
	auto t_name = tn + "->AsTypeList()";

	for ( const auto& tl_i : tl )
		AddInit(t, t_name + "->Append(" + GenTypeName(tl_i) + ");");
	}

void CPPCompile::ExpandRecordTypeVar(const TypePtr& t, string& tn)
	{
	auto r = t->AsRecordType()->Types();

	if ( ! r )
		return;

	auto t_name = tn + "->AsRecordType()";

	AddInit(t, string("if ( ") + t_name + "->NumFields() == 0 )");

	AddInit(t, "{");
	AddInit(t, "type_decl_list tl;");

	for ( auto i = 0; i < r->length(); ++i )
		{
		const auto& td = (*r)[i];
		AddInit(t, GenTypeDecl(td));
		}

	AddInit(t, t_name + "->AddFieldsDirectly(tl);");
	AddInit(t, "}");
	}

void CPPCompile::ExpandEnumTypeVar(const TypePtr& t, string& tn)
	{
	auto e_name = tn + "->AsEnumType()";
	auto et = t->AsEnumType();
	auto names = et->Names();

	AddInit(t, "{ auto et = " + e_name + ";");
	AddInit(t, "if ( et->Names().empty() ) {");

	for ( const auto& name_pair : et->Names() )
		AddInit(t, string("\tet->AddNameInternal(\"") +
		        name_pair.first + "\", " +
		        Fmt(int(name_pair.second)) + ");");

	AddInit(t, "}}");
	}

void CPPCompile::ExpandTableTypeVar(const TypePtr& t, string& tn)
	{
	auto tbl = t->AsTableType();

	const auto& indices = tbl->GetIndices();
	const auto& yield = tbl->Yield();

	if ( tbl->IsSet() )
		AddInit(t, tn,
		        string("make_intrusive<SetType>(cast_intrusive<TypeList>(") +
		        GenTypeName(indices) + " ), nullptr)");
	else
		AddInit(t, tn,
		        string("make_intrusive<TableType>(cast_intrusive<TypeList>(") +
		        GenTypeName(indices) + "), " +
		        GenTypeName(yield) + ")");
	}

void CPPCompile::ExpandFuncTypeVar(const TypePtr& t, string& tn)
	{
	auto f = t->AsFuncType();

	auto args_type_accessor = GenTypeName(f->Params());
	const auto& yt = f->Yield();

	string yield_type_accessor;

	if ( yt )
		yield_type_accessor += GenTypeName(yt);
	else
		yield_type_accessor += "nullptr";

	auto fl = f->Flavor();

	string fl_name;
	if ( fl == FUNC_FLAVOR_FUNCTION )
		fl_name = "FUNC_FLAVOR_FUNCTION";
	else if ( fl == FUNC_FLAVOR_EVENT )
		fl_name = "FUNC_FLAVOR_EVENT";
	else if ( fl == FUNC_FLAVOR_HOOK )
		fl_name = "FUNC_FLAVOR_HOOK";

	auto type_init = string("make_intrusive<FuncType>(cast_intrusive<RecordType>(") +
	                 args_type_accessor + "), " +
	                 yield_type_accessor + ", " + fl_name + ")";

	AddInit(t, tn, type_init);
	}

string CPPCompile::GenTypeDecl(const TypeDecl* td)
	{
	auto type_accessor = GenTypeName(td->type);

	auto td_name = string("util::copy_string(\"") + td->id + "\")";

	if ( td->attrs )
		return string("tl.append(new TypeDecl(") +
		       td_name + ", " + type_accessor +
		       ", " + AttrsName(td->attrs) +"));";

	return string("tl.append(new TypeDecl(") + td_name + ", " +
	       type_accessor +"));";
	}

string CPPCompile::GenTypeName(const Type* t)
	{
	return types.KeyName(TypeRep(t));
	}

const char* CPPCompile::TypeTagName(TypeTag tag) const
	{
	switch ( tag ) {
	case TYPE_ADDR:		return "TYPE_ADDR";
	case TYPE_ANY:		return "TYPE_ANY";
	case TYPE_BOOL:		return "TYPE_BOOL";
	case TYPE_COUNT:	return "TYPE_COUNT";
	case TYPE_DOUBLE:	return "TYPE_DOUBLE";
	case TYPE_ENUM:		return "TYPE_ENUM";
	case TYPE_ERROR:	return "TYPE_ERROR";
	case TYPE_FILE:		return "TYPE_FILE";
	case TYPE_FUNC:		return "TYPE_FUNC";
	case TYPE_INT:		return "TYPE_INT";
	case TYPE_INTERVAL:	return "TYPE_INTERVAL";
	case TYPE_OPAQUE:	return "TYPE_OPAQUE";
	case TYPE_PATTERN:	return "TYPE_PATTERN";
	case TYPE_PORT:		return "TYPE_PORT";
	case TYPE_RECORD:	return "TYPE_RECORD";
	case TYPE_STRING:	return "TYPE_STRING";
	case TYPE_SUBNET:	return "TYPE_SUBNET";
	case TYPE_TABLE:	return "TYPE_TABLE";
	case TYPE_TIME:		return "TYPE_TIME";
	case TYPE_TIMER:	return "TYPE_TIMER";
	case TYPE_TYPE:		return "TYPE_TYPE";
	case TYPE_VECTOR:	return "TYPE_VECTOR";
	case TYPE_VOID:		return "TYPE_VOID";

	default:
		reporter->InternalError("bad type in CPPCompile::TypeTagName");
		return nullptr;
	}
	}

const char* CPPCompile::TypeName(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:		return "bool";
	case TYPE_COUNT:	return "bro_uint_t";
	case TYPE_DOUBLE:	return "double";
	case TYPE_ENUM:		return "int";
	case TYPE_INT:		return "bro_int_t";
	case TYPE_INTERVAL:	return "double";
	case TYPE_PORT:		return "bro_uint_t";
	case TYPE_TIME:		return "double";
	case TYPE_VOID:		return "void";

	case TYPE_ADDR:		return "AddrVal";
	case TYPE_ANY:		return "Val";
	case TYPE_FILE:		return "FileVal";
	case TYPE_FUNC:		return "FuncVal";
	case TYPE_OPAQUE:	return "OpaqueVal";
	case TYPE_PATTERN:	return "PatternVal";
	case TYPE_RECORD:	return "RecordVal";
	case TYPE_STRING:	return "StringVal";
	case TYPE_SUBNET:	return "SubNetVal";
	case TYPE_TABLE:	return "TableVal";
	case TYPE_TYPE:		return "TypeVal";
	case TYPE_VECTOR:	return "VectorVal";

	default:
		reporter->InternalError("bad type in CPPCompile::TypeName");
		return nullptr;
	}
	}

const char* CPPCompile::FullTypeName(const TypePtr& t)
	{
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
	case TYPE_VOID:
		return TypeName(t);

	case TYPE_ADDR:		return "AddrValPtr";
	case TYPE_ANY:		return "ValPtr";
	case TYPE_FILE:		return "FileValPtr";
	case TYPE_FUNC:		return "FuncValPtr";
	case TYPE_OPAQUE:	return "OpaqueValPtr";
	case TYPE_PATTERN:	return "PatternValPtr";
	case TYPE_RECORD:	return "RecordValPtr";
	case TYPE_STRING:	return "StringValPtr";
	case TYPE_SUBNET:	return "SubNetValPtr";
	case TYPE_TABLE:	return "TableValPtr";
	case TYPE_TYPE:		return "TypeValPtr";
	case TYPE_VECTOR:	return "VectorValPtr";

	default:
		reporter->InternalError("bad type in CPPCompile::FullTypeName");
		return nullptr;
	}
	}

const char* CPPCompile::TypeType(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_RECORD:	return "RecordType";
	case TYPE_TABLE:	return "TableType";
	case TYPE_VECTOR:	return "VectorType";

	default:
		reporter->InternalError("bad type in CPPCompile::TypeType");
		return nullptr;
	}
	}

void CPPCompile::RegisterType(const TypePtr& tp)
	{
	auto t = TypeRep(tp);

	if ( processed_types.count(t) > 0 )
		return;

	// Add the type before going further, to avoid loops due to types
	// that reference each other.
	processed_types.insert(t);

	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ENUM:
	case TYPE_ERROR:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_PATTERN:
	case TYPE_PORT:
	case TYPE_STRING:
	case TYPE_TIME:
	case TYPE_TIMER:
	case TYPE_VOID:
	case TYPE_OPAQUE:
	case TYPE_SUBNET:
	case TYPE_FILE:
		// Nothing to do.
		break;

	case TYPE_TYPE:
		{
		const auto& tt = t->AsTypeType()->GetType();
		NoteNonRecordInitDependency(t, tt);
		RegisterType(tt);
		}
		break;

	case TYPE_VECTOR:
		{
		const auto& yield = t->AsVectorType()->Yield();
		NoteNonRecordInitDependency(t, yield);
		RegisterType(yield);
		}
		break;

	case TYPE_LIST:
		RegisterListType(tp);
		break;

	case TYPE_TABLE:
		RegisterTableType(tp);
		break;

	case TYPE_RECORD:
		RegisterRecordType(tp);
		break;

	case TYPE_FUNC:
		RegisterFuncType(tp);
		break;

	default:
		reporter->InternalError("bad type in CPPCompile::RegisterType");
	}

	AddInit(t);

	if ( ! types.IsInherited(t) )
		{
		auto t_rep = types.GetRep(t);
		if ( t_rep == t )
			GenPreInit(t);
		else
			NoteInitDependency(t, t_rep);
		}
	}

void CPPCompile::RegisterListType(const TypePtr& t)
	{
	const auto& tl = t->AsTypeList()->GetTypes();

	for ( auto& tl_i : tl )
		{
		NoteNonRecordInitDependency(t, tl_i);
		RegisterType(tl_i);
		}
	}

void CPPCompile::RegisterTableType(const TypePtr& t)
	{
	auto tbl = t->AsTableType();
	const auto& indices = tbl->GetIndices();
	const auto& yield = tbl->Yield();

	NoteNonRecordInitDependency(t, indices);
	RegisterType(indices);

	if ( yield )
		{
		NoteNonRecordInitDependency(t, yield);
		RegisterType(yield);
		}
	}

void CPPCompile::RegisterRecordType(const TypePtr& t)
	{
	auto r = t->AsRecordType()->Types();

	if ( ! r )
		return;

	for ( const auto& r_i : *r )
		{
		NoteNonRecordInitDependency(t, r_i->type);
		RegisterType(r_i->type);

		if ( r_i->attrs )
			{
			NoteInitDependency(t, r_i->attrs);
			RegisterAttributes(r_i->attrs);
			}
		}
	}

void CPPCompile::RegisterFuncType(const TypePtr& t)
	{
	auto f = t->AsFuncType();

	NoteInitDependency(t, TypeRep(f->Params()));
	RegisterType(f->Params());

	if ( f->Yield() )
		{
		NoteNonRecordInitDependency(t, f->Yield());
		RegisterType(f->Yield());
		}
	}

const char* CPPCompile::NativeAccessor(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:		return "->AsBool()";
	case TYPE_COUNT:	return "->AsCount()";
	case TYPE_DOUBLE:	return "->AsDouble()";
	case TYPE_ENUM:		return "->AsEnum()";
	case TYPE_INT:		return "->AsInt()";
	case TYPE_INTERVAL:	return "->AsDouble()";
	case TYPE_PORT:		return "->AsCount()";
	case TYPE_TIME:		return "->AsDouble()";

	case TYPE_ADDR:		return "->AsAddrVal()";
	case TYPE_FILE:		return "->AsFileVal()";
	case TYPE_FUNC:		return "->AsFuncVal()";
	case TYPE_OPAQUE:	return "->AsOpaqueVal()";
	case TYPE_PATTERN:	return "->AsPatternVal()";
	case TYPE_RECORD:	return "->AsRecordVal()";
	case TYPE_STRING:	return "->AsStringVal()";
	case TYPE_SUBNET:	return "->AsSubNetVal()";
	case TYPE_TABLE:	return "->AsTableVal()";
	case TYPE_TYPE:		return "->AsTypeVal()";
	case TYPE_VECTOR:	return "->AsVectorVal()";

	case TYPE_ANY:		return ".get()";

	case TYPE_VOID:		return "";

	default:
		reporter->InternalError("bad type in CPPCompile::NativeAccessor");
		return nullptr;
	}
	}

const char* CPPCompile::IntrusiveVal(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:		return "BoolVal";
	case TYPE_COUNT:	return "CountVal";
	case TYPE_DOUBLE:	return "DoubleVal";
	case TYPE_ENUM:		return "EnumVal";
	case TYPE_INT:		return "IntVal";
	case TYPE_INTERVAL:	return "IntervalVal";
	case TYPE_PORT:		return "PortVal";
	case TYPE_TIME:		return "TimeVal";

	case TYPE_ADDR:		return "AddrVal";
	case TYPE_ANY:		return "Val";
	case TYPE_FILE:		return "FileVal";
	case TYPE_FUNC:		return "FuncVal";
	case TYPE_OPAQUE:	return "OpaqueVal";
	case TYPE_PATTERN:	return "PatternVal";
	case TYPE_RECORD:	return "RecordVal";
	case TYPE_STRING:	return "StringVal";
	case TYPE_SUBNET:	return "SubNetVal";
	case TYPE_TABLE:	return "TableVal";
	case TYPE_TYPE:		return "TypeVal";
	case TYPE_VECTOR:	return "VectorVal";

	default:
		reporter->InternalError("bad type in CPPCompile::IntrusiveVal");
		return nullptr;
	}
	}

} // zeek::detail
