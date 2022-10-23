// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Type.h"

#include "zeek/zeek-config.h"

#include <list>
#include <map>
#include <string>

#include "zeek/Attr.h"
#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/Var.h"
#include "zeek/module_util.h"
#include "zeek/zeekygen/IdentifierInfo.h"
#include "zeek/zeekygen/Manager.h"
#include "zeek/zeekygen/ScriptInfo.h"
#include "zeek/zeekygen/utils.h"

using namespace std;

namespace zeek
	{

Type::TypeAliasMap Type::type_aliases;

// Note: This function must be thread-safe.
const char* type_name(TypeTag t)
	{
	static constexpr const char* type_names[int(NUM_TYPES)] = {
		"void", // 0
		"bool", // 1
		"int", // 2
		"count", // 3
		"double", // 4
		"time", // 5
		"interval", // 6
		"string", // 7
		"pattern", // 8
		"enum", // 9
		"port", // 10
		"addr", // 11
		"subnet", // 12
		"any", // 13
		"table", // 14
		"record", // 15
		"types", // 16
		"func", // 17
		"file", // 18
		"vector", // 19
		"opaque", // 20
		"type", // 21
		"error", // 22
	};

	if ( int(t) >= NUM_TYPES )
		return "type_name(): not a type tag";

	return type_names[int(t)];
	}

Type::Type(TypeTag t, bool arg_base_type)
	: tag(t), internal_tag(to_internal_type_tag(tag)), is_network_order(zeek::is_network_order(t)),
	  base_type(arg_base_type)
	{
	}

#define CHECK_TYPE_TAG(tag_type, func_name) CHECK_TAG(tag, tag_type, func_name, type_name)

const TypeList* Type::AsTypeList() const
	{
	CHECK_TYPE_TAG(TYPE_LIST, "Type::AsTypeList");
	return (const TypeList*)this;
	}

TypeList* Type::AsTypeList()
	{
	CHECK_TYPE_TAG(TYPE_LIST, "Type::AsTypeList");
	return (TypeList*)this;
	}

const TableType* Type::AsTableType() const
	{
	CHECK_TYPE_TAG(TYPE_TABLE, "Type::AsTableType");
	return (const TableType*)this;
	}

TableType* Type::AsTableType()
	{
	CHECK_TYPE_TAG(TYPE_TABLE, "Type::AsTableType");
	return (TableType*)this;
	}

const SetType* Type::AsSetType() const
	{
	if ( ! IsSet() )
		BadTag("Type::AsSetType", type_name(tag));
	return (const SetType*)this;
	}

SetType* Type::AsSetType()
	{
	if ( ! IsSet() )
		BadTag("Type::AsSetType", type_name(tag));
	return (SetType*)this;
	}

const RecordType* Type::AsRecordType() const
	{
	CHECK_TYPE_TAG(TYPE_RECORD, "Type::AsRecordType");
	return (const RecordType*)this;
	}

RecordType* Type::AsRecordType()
	{
	CHECK_TYPE_TAG(TYPE_RECORD, "Type::AsRecordType");
	return (RecordType*)this;
	}

const FuncType* Type::AsFuncType() const
	{
	CHECK_TYPE_TAG(TYPE_FUNC, "Type::AsFuncType");
	return (const FuncType*)this;
	}

FuncType* Type::AsFuncType()
	{
	CHECK_TYPE_TAG(TYPE_FUNC, "Type::AsFuncType");
	return (FuncType*)this;
	}

const FileType* Type::AsFileType() const
	{
	CHECK_TYPE_TAG(TYPE_FILE, "Type::AsFileType");
	return (const FileType*)this;
	}

FileType* Type::AsFileType()
	{
	CHECK_TYPE_TAG(TYPE_FILE, "Type::AsFileType");
	return (FileType*)this;
	}

const EnumType* Type::AsEnumType() const
	{
	CHECK_TYPE_TAG(TYPE_ENUM, "Type::AsEnumType");
	return (const EnumType*)this;
	}

EnumType* Type::AsEnumType()
	{
	CHECK_TYPE_TAG(TYPE_ENUM, "Type::AsEnumType");
	return (EnumType*)this;
	}

const VectorType* Type::AsVectorType() const
	{
	CHECK_TYPE_TAG(TYPE_VECTOR, "Type::AsVectorType");
	return (const VectorType*)this;
	}

VectorType* Type::AsVectorType()
	{
	CHECK_TYPE_TAG(TYPE_VECTOR, "Type::AsVectorType");
	return (VectorType*)this;
	}

const OpaqueType* Type::AsOpaqueType() const
	{
	CHECK_TYPE_TAG(TYPE_OPAQUE, "Type::AsOpaqueType");
	return (const OpaqueType*)this;
	}

OpaqueType* Type::AsOpaqueType()
	{
	CHECK_TYPE_TAG(TYPE_OPAQUE, "Type::AsOpaqueType");
	return (OpaqueType*)this;
	}

const TypeType* Type::AsTypeType() const
	{
	CHECK_TYPE_TAG(TYPE_TYPE, "Type::AsTypeType");
	return (const TypeType*)this;
	}

TypeType* Type::AsTypeType()
	{
	CHECK_TYPE_TAG(TYPE_TYPE, "Type::AsTypeType");
	return (TypeType*)this;
	}

TypePtr Type::ShallowClone()
	{
	switch ( tag )
		{
		case TYPE_VOID:
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_COUNT:
		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_STRING:
		case TYPE_PATTERN:
		case TYPE_PORT:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_ANY:
			return make_intrusive<Type>(tag, base_type);

		default:
			reporter->InternalError("cloning illegal base Type");
		}
	return nullptr;
	}

int Type::MatchesIndex(detail::ListExpr* const index) const
	{
	if ( Tag() == TYPE_STRING )
		{
		if ( index->Exprs().length() != 1 && index->Exprs().length() != 2 )
			return DOES_NOT_MATCH_INDEX;

		if ( check_and_promote_exprs_to_type(index, zeek::base_type(TYPE_INT)) )
			return MATCHES_INDEX_SCALAR;
		}

	return DOES_NOT_MATCH_INDEX;
	}

const TypePtr& Type::Yield() const
	{
	return Type::nil;
	}

void Type::Describe(ODesc* d) const
	{
	if ( ! d->IsBinary() && ! name.empty() )
		d->Add(name);
	else
		DoDescribe(d);
	}

void Type::DoDescribe(ODesc* d) const
	{
	if ( d->IsBinary() )
		d->Add(int(Tag()));
	else
		{
		TypeTag t = Tag();
		if ( IsSet() )
			d->Add("set");
		else
			d->Add(type_name(t));
		}
	}

void Type::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(util::fmt(":zeek:type:`%s`", type_name(Tag())));
	}

void Type::SetError()
	{
	tag = TYPE_ERROR;
	}

detail::TraversalCode Type::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreType(this);
	HANDLE_TC_TYPE_PRE(tc);

	tc = cb->PostType(this);
	HANDLE_TC_TYPE_POST(tc);
	}

void TypeList::CheckPure()
	{
	if ( pure_type )
		return;

	if ( ! types.empty() && AllMatch(types[0], false) )
		pure_type = types[0];
	}

bool TypeList::AllMatch(const Type* t, bool is_init) const
	{
	for ( const auto& type : types )
		if ( ! same_type(type, t, is_init) )
			return false;
	return true;
	}

void TypeList::Append(TypePtr t)
	{
	if ( pure_type && ! same_type(t, pure_type) )
		reporter->InternalError("pure type-list violation");

	types.emplace_back(std::move(t));
	}

void TypeList::AppendEvenIfNotPure(TypePtr t)
	{
	if ( pure_type && ! same_type(t, pure_type) )
		pure_type = nullptr;

	types.emplace_back(std::move(t));
	}

void TypeList::DoDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("list of");
	else
		{
		d->Add(int(Tag()));
		d->Add(IsPure());
		if ( IsPure() )
			pure_type->Describe(d);
		d->Add(static_cast<uint64_t>(types.size()));
		}

	if ( IsPure() )
		pure_type->Describe(d);
	else
		{
		for ( size_t i = 0; i < types.size(); ++i )
			{
			if ( i > 0 && ! d->IsBinary() )
				d->Add(",");

			types[i]->Describe(d);
			}
		}
	}

detail::TraversalCode TypeList::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreType(this);
	HANDLE_TC_TYPE_PRE(tc);

	for ( const auto& type : types )
		{
		tc = type->Traverse(cb);
		HANDLE_TC_TYPE_PRE(tc);
		}

	tc = cb->PostType(this);
	HANDLE_TC_TYPE_POST(tc);
	}

int IndexType::MatchesIndex(detail::ListExpr* const index) const
	{
	// If we have a type indexed by subnets, addresses are ok.
	const auto& types = indices->GetTypes();
	const ExprPList& exprs = index->Exprs();

	if ( types.size() == 1 && types[0]->Tag() == TYPE_SUBNET && exprs.length() == 1 &&
	     exprs[0]->GetType()->Tag() == TYPE_ADDR )
		return MATCHES_INDEX_SCALAR;

	return check_and_promote_exprs(index, GetIndices()) ? MATCHES_INDEX_SCALAR
	                                                    : DOES_NOT_MATCH_INDEX;
	}

void IndexType::DoDescribe(ODesc* d) const
	{
	Type::DoDescribe(d);
	if ( ! d->IsBinary() )
		d->Add("[");

	const auto& its = GetIndexTypes();

	for ( auto i = 0u; i < its.size(); ++i )
		{
		if ( ! d->IsBinary() && i > 0 )
			d->Add(",");
		its[i]->Describe(d);
		}
	if ( ! d->IsBinary() )
		d->Add("]");

	if ( yield_type )
		{
		if ( ! d->IsBinary() )
			d->Add(" of ");
		yield_type->Describe(d);
		}
	}

void IndexType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(":zeek:type:`");

	if ( IsSet() )
		d->Add("set");
	else
		d->Add(type_name(Tag()));

	d->Add("` ");
	d->Add("[");

	const auto& its = GetIndexTypes();

	for ( auto i = 0u; i < its.size(); ++i )
		{
		if ( i > 0 )
			d->Add(", ");

		const auto& t = its[i];

		if ( ! t->GetName().empty() )
			{
			d->Add(":zeek:type:`");
			d->Add(t->GetName());
			d->Add("`");
			}
		else
			t->DescribeReST(d, roles_only);
		}

	d->Add("]");

	if ( yield_type )
		{
		d->Add(" of ");

		if ( ! yield_type->GetName().empty() )
			{
			d->Add(":zeek:type:`");
			d->Add(yield_type->GetName());
			d->Add("`");
			}
		else
			yield_type->DescribeReST(d, roles_only);
		}
	}

bool IndexType::IsSubNetIndex() const
	{
	const auto& types = indices->GetTypes();
	if ( types.size() == 1 && types[0]->Tag() == TYPE_SUBNET )
		return true;
	return false;
	}

detail::TraversalCode IndexType::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreType(this);
	HANDLE_TC_TYPE_PRE(tc);

	for ( const auto& ind : GetIndexTypes() )
		{
		tc = ind->Traverse(cb);
		HANDLE_TC_TYPE_PRE(tc);
		}

	if ( yield_type )
		{
		tc = yield_type->Traverse(cb);
		HANDLE_TC_TYPE_PRE(tc);
		}

	tc = cb->PostType(this);
	HANDLE_TC_TYPE_POST(tc);
	}

static bool is_supported_index_type(const TypePtr& t, const char** tname)
	{
	if ( t->InternalType() != TYPE_INTERNAL_OTHER )
		return true;

	auto tag = t->Tag();

	switch ( tag )
		{
		// Allow functions, since they can be compared for Func* pointer equality.
		case TYPE_FUNC:
			return true;

		case TYPE_PATTERN:
			return true;

		case TYPE_RECORD:
			{
			auto rt = t->AsRecordType();

			for ( auto i = 0; i < rt->NumFields(); ++i )
				if ( ! is_supported_index_type(rt->GetFieldType(i), tname) )
					return false;

			return true;
			}

		case TYPE_LIST:
			{
			for ( const auto& type : t->AsTypeList()->GetTypes() )
				if ( ! is_supported_index_type(type, tname) )
					return false;

			return true;
			}

		case TYPE_TABLE:
			{
			auto tt = t->AsTableType();

			if ( ! is_supported_index_type(tt->GetIndices(), tname) )
				return false;

			const auto& yt = tt->Yield();

			if ( ! yt )
				return true;

			return is_supported_index_type(yt, tname);
			}

		case TYPE_VECTOR:
			return is_supported_index_type(t->AsVectorType()->Yield(), tname);

		default:
			*tname = type_name(tag);
			return false;
		}
	}

TableType::TableType(TypeListPtr ind, TypePtr yield)
	: IndexType(TYPE_TABLE, std::move(ind), std::move(yield))
	{
	if ( ! indices )
		return;

	const auto& tl = indices->GetTypes();
	const char* unsupported_type_name = nullptr;

	for ( const auto& tli : tl )
		{
		InternalTypeTag t = tli->InternalType();

		if ( t == TYPE_INTERNAL_ERROR )
			break;

		if ( ! is_supported_index_type(tli, &unsupported_type_name) )
			{
			auto msg = util::fmt("index type containing '%s' is not supported",
			                     unsupported_type_name);
			Error(msg, tli.get());
			SetError();
			break;
			}
		}
	}

bool TableType::CheckExpireFuncCompatibility(const detail::AttrPtr& attr)
	{
	if ( reported_error )
		return false;

	bool success = DoExpireCheck(attr);
	if ( ! success )
		reported_error = true;

	return success;
	}

TypePtr TableType::ShallowClone()
	{
	return make_intrusive<TableType>(indices, yield_type);
	}

bool TableType::IsUnspecifiedTable() const
	{
	// Unspecified types have an empty list of indices.
	return indices->GetTypes().empty();
	}

bool TableType::DoExpireCheck(const detail::AttrPtr& attr)
	{
	assert(attr->Tag() == detail::ATTR_EXPIRE_FUNC);

	const auto& expire_func = attr->GetExpr();

	if ( expire_func->GetType()->Tag() != TYPE_FUNC )
		{
		attr->Error("&expire_func attribute is not a function");
		return false;
		}

	const FuncType* e_ft = expire_func->GetType()->AsFuncType();

	if ( e_ft->Flavor() != FUNC_FLAVOR_FUNCTION )
		{
		attr->Error("&expire_func attribute is not a function");
		return false;
		}

	if ( e_ft->Yield()->Tag() != TYPE_INTERVAL )
		{
		attr->Error("&expire_func must yield a value of type interval");
		return false;
		}

	if ( IsUnspecifiedTable() )
		return true;

	const auto& func_index_types = e_ft->ParamList()->GetTypes();
	// Keep backwards compatibility with idx: any idiom.
	if ( func_index_types.size() == 2 )
		{
		if ( func_index_types[1]->Tag() == TYPE_ANY )
			return true;
		}

	const auto& table_index_types = GetIndexTypes();

	std::vector<TypePtr> expected_args;
	expected_args.reserve(1 + table_index_types.size());
	expected_args.emplace_back(NewRef{}, this);

	for ( const auto& t : table_index_types )
		expected_args.emplace_back(t);

	if ( ! e_ft->CheckArgs(expected_args) )
		{
		attr->Error("&expire_func argument type clash");
		return false;
		}

	return true;
	}

SetType::SetType(TypeListPtr ind, detail::ListExprPtr arg_elements)
	: TableType(std::move(ind), nullptr), elements(std::move(arg_elements))
	{
	if ( elements )
		{
		if ( indices )
			{ // We already have a type.
			if ( ! check_and_promote_exprs(elements.get(), indices) )
				SetError();
			}
		else
			{
			TypeList* tl_type = elements->GetType()->AsTypeList();
			const auto& tl = tl_type->GetTypes();

			if ( tl.size() < 1 )
				{
				Error("no type given for set");
				SetError();
				}

			else if ( tl.size() == 1 )
				{
				TypePtr ft{NewRef{}, flatten_type(tl[0].get())};
				indices = make_intrusive<TypeList>(ft);
				indices->Append(std::move(ft));
				}

			else
				{
				auto t = merge_types(tl[0], tl[1]);

				for ( size_t i = 2; t && i < tl.size(); ++i )
					t = merge_types(t, tl[i]);

				if ( ! t )
					{
					Error("bad set type");
					return;
					}

				indices = make_intrusive<TypeList>(t);
				indices->Append(std::move(t));
				}
			}
		}
	}

TypePtr SetType::ShallowClone()
	{
	return make_intrusive<SetType>(indices, elements);
	}

SetType::~SetType() = default;

FuncType::FuncType(RecordTypePtr arg_args, TypePtr arg_yield, FunctionFlavor arg_flavor)
	: Type(TYPE_FUNC), args(std::move(arg_args)), arg_types(make_intrusive<TypeList>()),
	  yield(std::move(arg_yield))
	{
	flavor = arg_flavor;

	bool has_default_arg = false;
	std::map<int, int> offsets;

	for ( int i = 0; i < args->NumFields(); ++i )
		{
		const TypeDecl* td = args->FieldDecl(i);

		if ( td->attrs && td->attrs->Find(detail::ATTR_DEFAULT) )
			has_default_arg = true;

		else if ( has_default_arg )
			{
			const char* err_str = util::fmt("required parameter '%s' must precede "
			                                "default parameters",
			                                td->id);
			args->Error(err_str);
			}

		arg_types->Append(args->GetFieldType(i));
		offsets[i] = i;
		}

	prototypes.emplace_back(Prototype{false, "", args, std::move(offsets)});
	}

TypePtr FuncType::ShallowClone()
	{
	auto f = make_intrusive<FuncType>();
	f->args = args;
	f->arg_types = arg_types;
	f->yield = yield;
	f->flavor = flavor;
	f->prototypes = prototypes;
	f->captures = captures;
	return f;
	}

string FuncType::FlavorString() const
	{
	switch ( flavor )
		{

		case FUNC_FLAVOR_FUNCTION:
			return "function";

		case FUNC_FLAVOR_EVENT:
			return "event";

		case FUNC_FLAVOR_HOOK:
			return "hook";

		default:
			reporter->InternalError("Invalid function flavor");
			return "invalid_func_flavor";
		}
	}

int FuncType::MatchesIndex(detail::ListExpr* const index) const
	{
	return check_and_promote_args(index, args.get()) ? MATCHES_INDEX_SCALAR : DOES_NOT_MATCH_INDEX;
	}

bool FuncType::CheckArgs(const TypePList* args, bool is_init, bool do_warn) const
	{
	std::vector<TypePtr> as;
	as.reserve(args->length());

	for ( auto a : *args )
		as.emplace_back(NewRef{}, a);

	return CheckArgs(as, is_init, do_warn);
	}

bool FuncType::CheckArgs(const std::vector<TypePtr>& args, bool is_init, bool do_warn) const
	{
	if ( reported_error )
		return false;

	const auto& my_args = arg_types->GetTypes();

	if ( my_args.size() != args.size() )
		{
		if ( do_warn )
			Warn(util::fmt("Wrong number of arguments for function. Expected %zu, got %zu.",
			               args.size(), my_args.size()));
		const_cast<FuncType*>(this)->reported_error = true;
		return false;
		}

	bool success = true;

	for ( size_t i = 0; i < my_args.size(); ++i )
		if ( ! same_type(args[i], my_args[i], is_init) )
			{
			if ( do_warn )
				Warn(util::fmt("Type mismatch in function argument #%zu. Expected %s, got %s.", i,
				               type_name(args[i]->Tag()), type_name(my_args[i]->Tag())));
			success = false;
			}

	const_cast<FuncType*>(this)->reported_error = ! success;

	return success;
	}

void FuncType::SetCaptures(std::optional<CaptureList> _captures)
	{
	captures = std::move(_captures);
	}

void FuncType::DoDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		{
		d->Add(FlavorString());
		d->Add("(");
		args->DescribeFields(d);
		d->Add(")");

		if ( yield )
			{
			d->AddSP(" :");
			yield->Describe(d);
			}
		}
	else
		{
		d->Add(int(Tag()));
		d->Add(flavor);
		d->Add(yield != nullptr);
		args->DescribeFields(d);
		if ( yield )
			yield->Describe(d);
		}
	}

void FuncType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(":zeek:type:`");
	d->Add(FlavorString());
	d->Add("`");
	d->Add(" (");
	args->DescribeFieldsReST(d, true);
	d->Add(")");

	if ( yield )
		{
		d->AddSP(" :");

		if ( ! yield->GetName().empty() )
			{
			d->Add(":zeek:type:`");
			d->Add(yield->GetName());
			d->Add("`");
			}
		else
			yield->DescribeReST(d, roles_only);
		}
	}

void FuncType::AddPrototype(Prototype p)
	{
	prototypes.emplace_back(std::move(p));
	}

std::optional<FuncType::Prototype> FuncType::FindPrototype(const RecordType& args) const
	{
	for ( auto i = 0u; i < prototypes.size(); ++i )
		{
		const auto& p = prototypes[i];

		if ( args.NumFields() != p.args->NumFields() )
			continue;

		if ( args.NumFields() == 0 )
			{
			if ( p.args->NumFields() == 0 )
				return p;

			continue;
			}

		bool matched = true;

		for ( auto i = 0; i < args.NumFields(); ++i )
			{
			const auto& ptype = p.args->GetFieldType(i);
			const auto& desired_type = args.GetFieldType(i);

			if ( ! same_type(ptype, desired_type) ||
			     ! util::streq(args.FieldName(i), p.args->FieldName(i)) )
				{
				matched = false;
				break;
				}
			}

		if ( matched )
			return p;
		}

	return {};
	}

detail::TraversalCode FuncType::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreType(this);
	HANDLE_TC_TYPE_PRE(tc);

	tc = args->Traverse(cb);
	HANDLE_TC_TYPE_PRE(tc);

	if ( yield )
		{
		tc = yield->Traverse(cb);
		HANDLE_TC_TYPE_PRE(tc);
		}

	tc = cb->PostType(this);
	HANDLE_TC_TYPE_POST(tc);
	}

detail::TraversalCode TypeType::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreType(this);
	HANDLE_TC_TYPE_PRE(tc);

	tc = type->Traverse(cb);
	HANDLE_TC_TYPE_PRE(tc);

	tc = cb->PostType(this);
	HANDLE_TC_TYPE_POST(tc);
	}

TypeDecl::TypeDecl(const char* i, TypePtr t, detail::AttributesPtr arg_attrs)
	: type(std::move(t)), attrs(std::move(arg_attrs)), id(i)
	{
	}

TypeDecl::TypeDecl(const TypeDecl& other)
	{
	type = other.type;
	attrs = other.attrs;

	id = util::copy_string(other.id);
	}

TypeDecl::~TypeDecl()
	{
	delete[] id;
	}

void TypeDecl::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(id);
	d->Add(": ");

	if ( ! type->GetName().empty() )
		{
		d->Add(":zeek:type:`");
		d->Add(type->GetName());
		d->Add("`");
		}
	else
		type->DescribeReST(d, roles_only);

	if ( attrs )
		{
		d->SP();
		attrs->DescribeReST(d);
		}
	}

// The following tracks how to initialize a given field, for fast execution
// of Create().

class FieldInit
	{
public:
	// The type of initialization for the field.
	enum
		{
		R_INIT_NONE, // skip this entry

		R_INIT_DIRECT, // look in direct_init for raw value
		R_INIT_DIRECT_MANAGED, // same, but managed type

		R_INIT_DEF, // look in def_expr for expression

		R_INIT_RECORD, // field requires a new record
		R_INIT_TABLE, // field requires a new table/set
		R_INIT_VECTOR, // field requires a new vector
		} init_type;

	bool def_coerce = false; // whether coercion's required

	// For R_INIT_DIRECT/R_INIT_DIRECT_MANAGED:
	ZVal direct_init;

	detail::ExprPtr def_expr;
	TypePtr def_type;

	RecordTypePtr r_type; // for R_INIT_RECORD
	TableTypePtr t_type; // for R_INIT_TABLE
	detail::AttributesPtr attrs; // attributes for R_INIT_TABLE
	VectorTypePtr v_type; // for R_INIT_VECTOR
	};

RecordType::RecordType(type_decl_list* arg_types) : Type(TYPE_RECORD)
	{
	types = arg_types;

	if ( types )
		{
		num_fields = types->length();

		loop_over_list(*types, i) AddField(i, (*types)[i]);
		}
	else
		num_fields = 0;

	num_orig_fields = num_fields;
	}

// in this case the clone is actually not so shallow, since
// it gets modified by everyone.
TypePtr RecordType::ShallowClone()
	{
	auto pass = new type_decl_list();
	for ( const auto& type : *types )
		pass->push_back(new TypeDecl(*type));
	return make_intrusive<RecordType>(pass);
	}

RecordType::~RecordType()
	{
	if ( types )
		{
		for ( auto type : *types )
			delete type;

		delete types;
		}

	for ( auto fi : field_inits )
		delete fi;
	}

void RecordType::AddField(unsigned int field, const TypeDecl* td)
	{
	ASSERT(field == field_inits.size());
	ASSERT(field == managed_fields.size());

	if ( field_ids.count(td->id) != 0 )
		{
		reporter->Error("Duplicate field '%s' found in record definition\n", td->id);
		return;
		}
	else
		{
		field_ids.insert(std::string(td->id));
		}

	managed_fields.push_back(ZVal::IsManagedType(td->type));

	auto init = new FieldInit();
	init->init_type = FieldInit::R_INIT_NONE;

	init->attrs = td->attrs;
	auto a = init->attrs;

	auto type = td->type;

	auto def_attr = a ? a->Find(detail::ATTR_DEFAULT) : nullptr;
	auto def_expr = def_attr ? def_attr->GetExpr() : nullptr;

	if ( def_expr )
		{
		if ( type->Tag() == TYPE_RECORD && def_expr->GetType()->Tag() == TYPE_RECORD &&
		     ! same_type(def_expr->GetType(), type) )
			init->def_coerce = true;

		if ( def_expr->Tag() == detail::EXPR_CONST )
			{
			auto v = def_expr->Eval(nullptr);

			if ( ZVal::IsManagedType(type) )
				init->init_type = FieldInit::R_INIT_DIRECT_MANAGED;
			else
				init->init_type = FieldInit::R_INIT_DIRECT;

			init->direct_init = ZVal(v, type);
			}

		else
			{
			init->init_type = FieldInit::R_INIT_DEF;
			init->def_expr = def_expr;
			init->def_type = def_expr->GetType();
			}
		}

	else if ( ! (a && a->Find(detail::ATTR_OPTIONAL)) )
		{
		TypeTag tag = type->Tag();

		if ( tag == TYPE_RECORD )
			{
			init->init_type = FieldInit::R_INIT_RECORD;
			init->r_type = cast_intrusive<RecordType>(type);
			}

		else if ( tag == TYPE_TABLE )
			{
			init->init_type = FieldInit::R_INIT_TABLE;
			init->t_type = cast_intrusive<TableType>(type);
			}

		else if ( tag == TYPE_VECTOR )
			{
			init->init_type = FieldInit::R_INIT_VECTOR;
			init->v_type = cast_intrusive<VectorType>(type);
			}
		}

	field_inits.push_back(init);
	}

bool RecordType::HasField(const char* field) const
	{
	return field_ids.count(field) != 0;
	}

ValPtr RecordType::FieldDefault(int field) const
	{
	const TypeDecl* td = FieldDecl(field);

	if ( ! td->attrs )
		return nullptr;

	const auto& def_attr = td->attrs->Find(detail::ATTR_DEFAULT);
	return def_attr ? def_attr->GetExpr()->Eval(nullptr) : nullptr;
	}

int RecordType::FieldOffset(const char* field) const
	{
	loop_over_list(*types, i)
		{
		TypeDecl* td = (*types)[i];
		if ( util::streq(td->id, field) )
			return i;
		}

	return -1;
	}

const char* RecordType::FieldName(int field) const
	{
	return FieldDecl(field)->id;
	}

const TypeDecl* RecordType::FieldDecl(int field) const
	{
	return (*types)[field];
	}

TypeDecl* RecordType::FieldDecl(int field)
	{
	return (*types)[field];
	}

void RecordType::DoDescribe(ODesc* d) const
	{
	d->PushType(this);

	if ( d->IsReadable() )
		{
		if ( d->IsShort() && GetName().size() )
			d->Add(GetName());

		else
			{
			d->AddSP("record {");
			DescribeFields(d);
			d->SP();
			d->Add("}");
			}
		}

	else
		{
		d->Add(int(Tag()));
		DescribeFields(d);
		}

	d->PopType(this);
	}

void RecordType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->PushType(this);
	d->Add(":zeek:type:`record`");

	if ( num_fields == 0 )
		return;

	d->NL();
	DescribeFieldsReST(d, false);
	d->PopType(this);
	}

static string container_type_name(const Type* ft)
	{
	string s;
	if ( ft->Tag() == TYPE_RECORD )
		s = "record " + ft->GetName();
	else if ( ft->Tag() == TYPE_VECTOR )
		s = "vector of " + container_type_name(ft->Yield().get());
	else if ( ft->Tag() == TYPE_TABLE )
		{
		if ( ft->IsSet() )
			s = "set[";
		else
			s = "table[";

		const auto& tl = ((const IndexType*)ft)->GetIndexTypes();

		for ( auto i = 0u; i < tl.size(); ++i )
			{
			if ( i > 0 )
				s += ",";
			s += container_type_name(tl[i].get());
			}
		s += "]";
		if ( ft->Yield() )
			{
			s += " of ";
			s += container_type_name(ft->Yield().get());
			}
		}
	else
		s = type_name(ft->Tag());
	return s;
	}

TableValPtr RecordType::GetRecordFieldsVal(const RecordVal* rv) const
	{
	static auto record_field = id::find_type<RecordType>("record_field");
	static auto record_field_table = id::find_type<TableType>("record_field_table");
	auto rval = make_intrusive<TableVal>(record_field_table);

	for ( int i = 0; i < NumFields(); ++i )
		{
		const auto& ft = GetFieldType(i);
		const TypeDecl* fd = FieldDecl(i);
		ValPtr fv;

		if ( rv )
			fv = rv->GetField(i);

		bool logged = (fd->attrs && fd->GetAttr(detail::ATTR_LOG) != nullptr);

		auto nr = make_intrusive<RecordVal>(record_field);

		string s = container_type_name(ft.get());
		nr->Assign(0, s);
		nr->Assign(1, logged);
		nr->Assign(2, std::move(fv));
		nr->Assign(3, FieldDefault(i));
		auto field_name = make_intrusive<StringVal>(FieldName(i));
		rval->Assign(std::move(field_name), std::move(nr));
		}

	return rval;
	}

const char* RecordType::AddFields(const type_decl_list& others, bool add_log_attr)
	{
	assert(types);

	bool log = false;

	for ( const auto& td : others )
		{
		if ( ! td->GetAttr(detail::ATTR_DEFAULT) && ! td->GetAttr(detail::ATTR_OPTIONAL) )
			return "extension field must be &optional or have &default";
		}

	TableVal::SaveParseTimeTableState(this);

	AddFieldsDirectly(others, add_log_attr);

	RecordVal::ResizeParseTimeRecords(this);
	TableVal::RebuildParseTimeTables();

	return nullptr;
	}

void RecordType::AddFieldsDirectly(const type_decl_list& others, bool add_log_attr)
	{
	for ( const auto& td : others )
		{
		if ( add_log_attr )
			{
			if ( ! td->attrs )
				td->attrs = make_intrusive<detail::Attributes>(td->type, true, false);

			td->attrs->AddAttr(make_intrusive<detail::Attr>(detail::ATTR_LOG));
			}

		int field = types->size();
		types->push_back(td);
		AddField(field, td);
		}

	num_fields = types->length();
	}

void RecordType::Create(std::vector<std::optional<ZVal>>& r) const
	{
	int n = NumFields();

	for ( int i = 0; i < n; ++i )
		{
		auto& init = field_inits[i];

		ZVal r_i;

		switch ( init->init_type )
			{
			case FieldInit::R_INIT_NONE:
				r.push_back(std::nullopt);
				continue;

			case FieldInit::R_INIT_DIRECT:
				r_i = init->direct_init;
				break;

			case FieldInit::R_INIT_DIRECT_MANAGED:
				r_i = init->direct_init;
				zeek::Ref(r_i.ManagedVal());
				break;

			case FieldInit::R_INIT_DEF:
				{
				auto v = init->def_expr->Eval(nullptr);
				if ( v )
					{
					const auto& t = init->def_type;

					if ( init->def_coerce )
						{
						auto rt = cast_intrusive<RecordType>(t);
						v = v->AsRecordVal()->CoerceTo(rt);
						}

					r_i = ZVal(v, t);
					}
				else
					reporter->Error("failed &default in record creation");
				}
				break;

			case FieldInit::R_INIT_RECORD:
				r_i = ZVal(new RecordVal(init->r_type));
				break;

			case FieldInit::R_INIT_TABLE:
				r_i = ZVal(new TableVal(init->t_type, init->attrs));
				break;

			case FieldInit::R_INIT_VECTOR:
				r_i = ZVal(new VectorVal(init->v_type));
				break;
			}

		r.push_back(r_i);
		}
	}

void RecordType::DescribeFields(ODesc* d) const
	{
	if ( d->IsReadable() )
		{
		for ( int i = 0; i < num_fields; ++i )
			{
			if ( i > 0 )
				d->SP();

			const TypeDecl* td = FieldDecl(i);
			d->Add(td->id);
			d->Add(":");

			if ( d->FindType(td->type.get()) )
				d->Add("<recursion>");
			else
				td->type->Describe(d);

			if ( td->attrs )
				{
				d->SP();
				td->attrs->Describe(d);
				}

			d->Add(";");
			}
		}

	else
		{
		if ( types )
			{
			d->AddCount(0);
			d->AddCount(types->length());
			for ( const auto& type : *types )
				{
				d->Add(type->id);
				d->SP();

				if ( d->FindType(type->type.get()) )
					d->Add("<recursion>");
				else
					type->type->Describe(d);

				d->SP();
				}
			}
		}
	}

void RecordType::DescribeFieldsReST(ODesc* d, bool func_args) const
	{
	if ( ! func_args )
		d->PushIndent();

	for ( int i = 0; i < num_fields; ++i )
		{
		if ( i > 0 )
			{
			if ( func_args )
				d->Add(", ");
			else
				{
				d->NL();
				d->NL();
				}
			}

		const TypeDecl* td = FieldDecl(i);

		if ( d->FindType(td->type.get()) )
			d->Add("<recursion>");
		else
			{
			if ( num_fields == 1 && util::streq(td->id, "va_args") && td->type->Tag() == TYPE_ANY )
				// This was a BIF using variable argument list
				d->Add("...");
			else
				td->DescribeReST(d);
			}

		if ( func_args )
			continue;

		zeekygen::detail::IdentifierInfo* doc = detail::zeekygen_mgr->GetIdentifierInfo(GetName());

		if ( ! doc )
			{
			reporter->InternalWarning("Failed to lookup record doc: %s", GetName().c_str());
			continue;
			}

		string field_from_script = doc->GetDeclaringScriptForField(td->id);
		string type_from_script;

		if ( doc->GetDeclaringScript() )
			type_from_script = doc->GetDeclaringScript()->Name();

		if ( ! field_from_script.empty() && field_from_script != type_from_script )
			{
			d->PushIndent();
			d->Add(zeekygen::detail::redef_indication(field_from_script).c_str());
			d->PopIndent();
			}

		vector<string> cmnts = doc->GetFieldComments(td->id);

		if ( cmnts.empty() )
			continue;

		d->PushIndent();

		for ( size_t i = 0; i < cmnts.size(); ++i )
			{
			if ( i > 0 )
				d->NL();

			if ( IsFunc(td->type->Tag()) )
				{
				string s = cmnts[i];

				if ( zeekygen::detail::prettify_params(s) )
					d->NL();

				d->Add(s.c_str());
				}
			else
				d->Add(cmnts[i].c_str());
			}

		d->PopIndentNoNL();
		}

	if ( ! func_args )
		d->PopIndentNoNL();
	}

string RecordType::GetFieldDeprecationWarning(int field, bool has_check) const
	{
	const TypeDecl* decl = FieldDecl(field);
	if ( decl )
		{
		string result;
		if ( const auto& deprecation = decl->GetAttr(detail::ATTR_DEPRECATED) )
			result = deprecation->DeprecationMessage();

		if ( result.empty() )
			return util::fmt("deprecated (%s%s$%s)", GetName().c_str(), has_check ? "?" : "",
			                 FieldName(field));
		else
			return util::fmt("deprecated (%s%s$%s): %s", GetName().c_str(), has_check ? "?" : "",
			                 FieldName(field), result.c_str());
		}

	return "";
	}

detail::TraversalCode RecordType::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreType(this);
	HANDLE_TC_TYPE_PRE(tc);

	if ( types )
		for ( const auto& td : *types )
			{
			tc = td->type->Traverse(cb);
			HANDLE_TC_TYPE_PRE(tc);

			if ( td->attrs )
				{
				tc = td->attrs->Traverse(cb);
				HANDLE_TC_TYPE_PRE(tc);
				}
			}

	tc = cb->PostType(this);
	HANDLE_TC_TYPE_POST(tc);
	}

FileType::FileType(TypePtr yield_type) : Type(TYPE_FILE), yield(std::move(yield_type)) { }

FileType::~FileType() = default;

void FileType::DoDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		{
		d->AddSP("file of");
		yield->Describe(d);
		}
	else
		{
		d->Add(int(Tag()));
		yield->Describe(d);
		}
	}

detail::TraversalCode FileType::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreType(this);
	HANDLE_TC_TYPE_PRE(tc);

	tc = yield->Traverse(cb);
	HANDLE_TC_TYPE_PRE(tc);

	tc = cb->PostType(this);
	HANDLE_TC_TYPE_POST(tc);
	}

OpaqueType::OpaqueType(const string& arg_name) : Type(TYPE_OPAQUE)
	{
	name = arg_name;
	}

void OpaqueType::DoDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("opaque of");
	else
		d->Add(int(Tag()));

	d->Add(name.c_str());
	}

void OpaqueType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(util::fmt(":zeek:type:`%s` of %s", type_name(Tag()), name.c_str()));
	}

EnumType::EnumType(const string& name) : Type(TYPE_ENUM)
	{
	counter = 0;
	SetName(name);
	}

EnumType::EnumType(const EnumType* e) : Type(TYPE_ENUM), names(e->names), vals(e->vals)
	{
	counter = e->counter;
	SetName(e->GetName());
	}

TypePtr EnumType::ShallowClone()
	{
	if ( counter == 0 )
		return make_intrusive<EnumType>(GetName());

	return make_intrusive<EnumType>(this);
	}

EnumType::~EnumType() = default;

// Note, we use reporter->Error() here (not Error()) to include the current script
// location in the error message, rather than the one where the type was
// originally defined.
void EnumType::AddName(const string& module_name, const char* name, bool is_export,
                       detail::Expr* deprecation, bool from_redef)
	{
	/* implicit, auto-increment */
	if ( counter < 0 )
		{
		reporter->Error("cannot mix explicit enumerator assignment and implicit auto-increment");
		SetError();
		return;
		}
	CheckAndAddName(module_name, name, counter, is_export, deprecation, from_redef);
	counter++;
	}

void EnumType::AddName(const string& module_name, const char* name, zeek_int_t val, bool is_export,
                       detail::Expr* deprecation, bool from_redef)
	{
	/* explicit value specified */
	if ( counter > 0 )
		{
		reporter->Error("cannot mix explicit enumerator assignment and implicit auto-increment");
		SetError();
		return;
		}
	counter = -1;
	CheckAndAddName(module_name, name, val, is_export, deprecation, from_redef);
	}

void EnumType::CheckAndAddName(const string& module_name, const char* name, zeek_int_t val,
                               bool is_export, detail::Expr* deprecation, bool from_redef)
	{
	if ( from_redef )
		has_redefs = true;

	if ( Lookup(val) )
		{
		reporter->Error("enumerator value in enumerated type definition already exists");
		SetError();
		return;
		}

	auto fullname = detail::make_full_var_name(module_name.c_str(), name);
	auto id = id::find(fullname);

	if ( ! id )
		{
		id = detail::install_ID(name, module_name.c_str(), true, is_export);
		id->SetType({NewRef{}, this});
		id->SetEnumConst();

		if ( deprecation )
			id->MakeDeprecated({NewRef{}, deprecation});

		detail::zeekygen_mgr->Identifier(std::move(id), from_redef);
		}
	else
		{
		// We allow double-definitions if matching exactly. This is so that
		// we can define an enum both in a *.bif and *.zeek for avoiding
		// cyclic dependencies.
		if ( ! id->IsEnumConst() || (id->HasVal() && val != id->GetVal()->AsEnum()) ||
		     GetName() != id->GetType()->GetName() ||
		     (names.find(fullname) != names.end() && names[fullname] != val) )
			{
			auto cl = detail::GetCurrentLocation();
			reporter->PushLocation(&cl, id->GetLocationInfo());
			reporter->Error("conflicting definition of enum value '%s' in type '%s'",
			                fullname.data(), GetName().data());
			reporter->PopLocation();
			SetError();
			return;
			}
		}

	AddNameInternal(module_name, name, val, is_export);

	if ( vals.find(val) == vals.end() )
		vals[val] = make_intrusive<EnumVal>(IntrusivePtr{NewRef{}, this}, val);

	const auto& types = Type::Aliases(GetName());

	for ( const auto& t : types )
		if ( t.get() != this )
			t->AsEnumType()->AddNameInternal(module_name, name, val, is_export);
	}

void EnumType::AddNameInternal(const string& module_name, const char* name, zeek_int_t val,
                               bool is_export)
	{
	string fullname = detail::make_full_var_name(module_name.c_str(), name);
	names[fullname] = val;
	}

void EnumType::AddNameInternal(const string& full_name, zeek_int_t val)
	{
	names[full_name] = val;

	if ( vals.find(val) == vals.end() )
		vals[val] = make_intrusive<EnumVal>(IntrusivePtr{NewRef{}, this}, val);
	}

zeek_int_t EnumType::Lookup(const string& module_name, const char* name) const
	{
	return Lookup(detail::make_full_var_name(module_name.c_str(), name));
	}

zeek_int_t EnumType::Lookup(const string& full_name) const
	{
	NameMap::const_iterator pos = names.find(full_name.c_str());

	if ( pos == names.end() )
		return -1;
	else
		return pos->second;
	}

const char* EnumType::Lookup(zeek_int_t value) const
	{
	for ( NameMap::const_iterator iter = names.begin(); iter != names.end(); ++iter )
		if ( iter->second == value )
			return iter->first.c_str();

	return nullptr;
	}

EnumType::enum_name_list EnumType::Names() const
	{
	enum_name_list n;
	for ( NameMap::const_iterator iter = names.begin(); iter != names.end(); ++iter )
		n.push_back(std::make_pair(iter->first, iter->second));

	return n;
	}

const EnumValPtr& EnumType::GetEnumVal(zeek_int_t i)
	{
	auto it = vals.find(i);

	if ( it == vals.end() )
		{
		auto ev = make_intrusive<EnumVal>(IntrusivePtr{NewRef{}, this}, i);
		return vals.emplace(i, std::move(ev)).first->second;
		}

	return it->second;
	}

void EnumType::DoDescribe(ODesc* d) const
	{
	auto t = Tag();

	if ( d->IsBinary() )
		{
		d->Add(int(t));
		if ( ! d->IsShort() )
			d->Add(GetName());
		}
	else
		{
		d->Add(type_name(t));
		if ( ! d->IsShort() )
			{
			d->SP();
			d->Add(GetName());
			}
		}
	}

void EnumType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(":zeek:type:`enum`");

	// Create temporary, reverse name map so that enums can be documented
	// in ascending order of their actual integral value instead of by name.
	using RevNameMap = std::map<zeek_int_t, std::string>;
	RevNameMap rev;

	for ( NameMap::const_iterator it = names.begin(); it != names.end(); ++it )
		rev[it->second] = it->first;

	for ( RevNameMap::const_iterator it = rev.begin(); it != rev.end(); ++it )
		{
		d->NL();
		d->PushIndent();

		if ( roles_only )
			d->Add(util::fmt(":zeek:enum:`%s`", it->second.c_str()));
		else
			d->Add(util::fmt(".. zeek:enum:: %s %s", it->second.c_str(), GetName().c_str()));

		zeekygen::detail::IdentifierInfo* doc = detail::zeekygen_mgr->GetIdentifierInfo(it->second);

		if ( ! doc )
			{
			reporter->InternalWarning("Enum %s documentation lookup failure", it->second.c_str());
			continue;
			}

		string enum_from_script;
		string type_from_script;

		if ( doc->GetDeclaringScript() )
			enum_from_script = doc->GetDeclaringScript()->Name();

		zeekygen::detail::IdentifierInfo* type_doc = detail::zeekygen_mgr->GetIdentifierInfo(
			GetName());

		if ( type_doc && type_doc->GetDeclaringScript() )
			type_from_script = type_doc->GetDeclaringScript()->Name();

		if ( ! enum_from_script.empty() && enum_from_script != type_from_script )
			{
			d->NL();
			d->PushIndent();
			d->Add(zeekygen::detail::redef_indication(enum_from_script).c_str());
			d->PopIndent();
			}

		vector<string> cmnts = doc->GetComments();

		if ( cmnts.empty() )
			{
			d->PopIndentNoNL();
			continue;
			}

		d->NL();
		d->PushIndent();

		for ( size_t i = 0; i < cmnts.size(); ++i )
			{
			if ( i > 0 )
				d->NL();

			d->Add(cmnts[i].c_str());
			}

		d->PopIndentNoNL();
		d->PopIndentNoNL();
		}
	}

VectorType::VectorType(TypePtr element_type)
	: Type(TYPE_VECTOR), yield_type(std::move(element_type))
	{
	}

TypePtr VectorType::ShallowClone()
	{
	return make_intrusive<VectorType>(yield_type);
	}

VectorType::~VectorType() = default;

const TypePtr& VectorType::Yield() const
	{
	// Work around the fact that we use void internally to mark a vector
	// as being unspecified. When looking at its yield type, we need to
	// return any as that's what other code historically expects for type
	// comparisons.
	if ( IsUnspecifiedVector() )
		return zeek::base_type(TYPE_ANY);

	return yield_type;
	}

int VectorType::MatchesIndex(detail::ListExpr* const index) const
	{
	ExprPList& el = index->Exprs();

	if ( el.length() != 1 && el.length() != 2 )
		return DOES_NOT_MATCH_INDEX;

	if ( el.length() == 2 )
		return MATCHES_INDEX_VECTOR;
	else if ( el[0]->GetType()->Tag() == TYPE_VECTOR )
		return (IsIntegral(el[0]->GetType()->Yield()->Tag()) ||
		        IsBool(el[0]->GetType()->Yield()->Tag()))
		           ? MATCHES_INDEX_VECTOR
		           : DOES_NOT_MATCH_INDEX;
	else
		return (IsIntegral(el[0]->GetType()->Tag()) || IsBool(el[0]->GetType()->Tag()))
		           ? MATCHES_INDEX_SCALAR
		           : DOES_NOT_MATCH_INDEX;
	}

bool VectorType::IsUnspecifiedVector() const
	{
	return yield_type->Tag() == TYPE_VOID;
	}

void VectorType::DoDescribe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("vector of");
	else
		d->Add(int(Tag()));

	yield_type->Describe(d);
	}

void VectorType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(util::fmt(":zeek:type:`%s` of ", type_name(Tag())));

	if ( yield_type->GetName().empty() )
		yield_type->DescribeReST(d, roles_only);
	else
		d->Add(util::fmt(":zeek:type:`%s`", yield_type->GetName().c_str()));
	}

detail::TraversalCode VectorType::Traverse(detail::TraversalCallback* cb) const
	{
	auto tc = cb->PreType(this);
	HANDLE_TC_TYPE_PRE(tc);

	tc = yield_type->Traverse(cb);
	HANDLE_TC_TYPE_PRE(tc);

	tc = cb->PostType(this);
	HANDLE_TC_TYPE_POST(tc);
	}

// Returns true if t1 is initialization-compatible with t2 (i.e., if an
// initializer with type t1 can be used to initialize a value with type t2),
// false otherwise.  Assumes that t1's tag is different from t2's.  Note
// that the test is in only one direction - we don't check whether t2 is
// initialization-compatible with t1.
static bool is_init_compat(const Type& t1, const Type& t2)
	{
	if ( t1.Tag() == TYPE_LIST )
		{
		if ( t2.Tag() == TYPE_RECORD )
			return true;
		else
			return t1.AsTypeList()->AllMatch(&t2, true);
		}

	if ( t1.IsSet() )
		return same_type(*t1.AsSetType()->GetIndices(), t2, true);

	return false;
	}

bool same_type(const Type& arg_t1, const Type& arg_t2, bool is_init, bool match_record_field_names)
	{
	if ( &arg_t1 == &arg_t2 || arg_t1.Tag() == TYPE_ANY || arg_t2.Tag() == TYPE_ANY )
		return true;

	auto t1 = &arg_t1;
	auto t2 = &arg_t2;

	if ( t1->Tag() != t2->Tag() )
		{
		if ( is_init )
			return is_init_compat(*t1, *t2) || is_init_compat(*t2, *t1);

		return false;
		}

	// A major complication we have to deal with is the potential
	// presence of recursive types (records, in particular).  If
	// we simply traverse a type's members recursively, then if the
	// type is itself recursive we will end up with infinite recursion.
	// To prevent this, we need to instead track our analysis process

	// Which types we're in the process of analyzing.  We add (compound)
	// types to this as we recurse into their elements, and remove them
	// when we're done processing them.
	static std::unordered_set<const Type*> analyzed_types;

	// First do all checks that don't require any recursion.

	switch ( t1->Tag() )
		{
		case TYPE_VOID:
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_COUNT:
		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_STRING:
		case TYPE_PATTERN:
		case TYPE_PORT:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_ANY:
		case TYPE_ERROR:
			return true;

		case TYPE_ENUM:
			// We should probably check to see whether all of the
			// enumerations are present and in the same location.
			// FIXME: Yes, but perhaps we should better return
			// true per default?
			return true;

		case TYPE_OPAQUE:
			{
			const OpaqueType* ot1 = (const OpaqueType*)t1;
			const OpaqueType* ot2 = (const OpaqueType*)t2;
			return ot1->Name() == ot2->Name();
			}

		case TYPE_TABLE:
			{
			const IndexType* it1 = (const IndexType*)t1;
			const IndexType* it2 = (const IndexType*)t2;

			const auto& tl1 = it1->GetIndices();
			const auto& tl2 = it2->GetIndices();

			if ( (tl1 || tl2) && ! (tl1 && tl2) )
				return false;

			// If one is a set and one isn't, they shouldn't
			// be considered the same type.
			if ( (t1->IsSet() && ! t2->IsSet()) || (t2->IsSet() && ! t1->IsSet()) )
				return false;

			const auto& y1 = t1->Yield();
			const auto& y2 = t2->Yield();

			if ( (y1 || y2) && ! (y1 && y2) )
				return false;

			break;
			}

		case TYPE_FUNC:
			{
			const FuncType* ft1 = (const FuncType*)t1;
			const FuncType* ft2 = (const FuncType*)t2;

			if ( ft1->Flavor() != ft2->Flavor() )
				return false;

			const auto& y1 = t1->Yield();
			const auto& y2 = t2->Yield();
			if ( (y1 || y2) && ! (y1 && y2) )
				return false;

			break;
			}

		case TYPE_RECORD:
			{
			const RecordType* rt1 = (const RecordType*)t1;
			const RecordType* rt2 = (const RecordType*)t2;

			if ( rt1->NumFields() != rt2->NumFields() )
				return false;

			for ( int i = 0; i < rt1->NumFields(); ++i )
				{
				const TypeDecl* td1 = rt1->FieldDecl(i);
				const TypeDecl* td2 = rt2->FieldDecl(i);

				if ( match_record_field_names && ! util::streq(td1->id, td2->id) )
					return false;

				if ( ! same_attrs(td1->attrs.get(), td2->attrs.get()) )
					return false;
				}

			break;
			}

		case TYPE_LIST:
			{
			const auto& tl1 = t1->AsTypeList()->GetTypes();
			const auto& tl2 = t2->AsTypeList()->GetTypes();

			if ( tl1.size() != tl2.size() )
				return false;

			break;
			}

		case TYPE_VECTOR:
		case TYPE_FILE:
		case TYPE_TYPE:
			break;
		}

	// If we get to here, then we're dealing with a type with
	// subtypes, and thus potentially recursive.

	if ( analyzed_types.count(t1) > 0 || analyzed_types.count(t2) > 0 )
		{
		// We've analyzed at least one of the types previously.
		// Avoid infinite recursion.

		if ( analyzed_types.count(t1) > 0 && analyzed_types.count(t2) > 0 )
			// We've analyzed them both.  In theory, this
			// could happen while the types are still different.
			// Checking for that is a pain - we could do so
			// by recursively expanding all of the types present
			// when traversing them (suppressing repeats), and
			// see that they individually match in a non-recursive
			// manner.  For now, we assume they're a direct match.
			return true;

		// One is definitely recursive and the other has not yet
		// manifested as such.  In theory, they again could still
		// be a match, if the non-recursive one would manifest
		// becoming recursive if only we traversed it further, but
		// for now we assume they're not a match.
		return false;
		}

	// Track the two types for when we recurse.
	analyzed_types.insert(t1);
	analyzed_types.insert(t2);

	bool result;

	switch ( t1->Tag() )
		{
		case TYPE_TABLE:
			{
			const IndexType* it1 = (const IndexType*)t1;
			const IndexType* it2 = (const IndexType*)t2;

			const auto& tl1 = it1->GetIndices();
			const auto& tl2 = it2->GetIndices();

			if ( ! same_type(tl1, tl2, is_init, match_record_field_names) )
				result = false;
			else if ( t1->IsSet() && t2->IsSet() )
				// Sets don't have yield types because they don't have values. If
				// both types are sets, and we already matched on the indices
				// above consider that a success. We already checked the case
				// where only one of the two is a set earlier.
				result = true;
			else
				{
				const auto& y1 = t1->Yield();
				const auto& y2 = t2->Yield();

				result = same_type(y1, y2, is_init, match_record_field_names);
				}
			break;
			}

		case TYPE_FUNC:
			{
			const FuncType* ft1 = (const FuncType*)t1;
			const FuncType* ft2 = (const FuncType*)t2;

			if ( ! same_type(t1->Yield(), t2->Yield(), is_init, match_record_field_names) )
				result = false;
			else
				result = ft1->CheckArgs(ft2->ParamList()->GetTypes(), is_init, false);
			break;
			}

		case TYPE_RECORD:
			{
			const RecordType* rt1 = (const RecordType*)t1;
			const RecordType* rt2 = (const RecordType*)t2;

			result = true;

			for ( int i = 0; i < rt1->NumFields(); ++i )
				{
				const TypeDecl* td1 = rt1->FieldDecl(i);
				const TypeDecl* td2 = rt2->FieldDecl(i);

				if ( ! same_type(td1->type, td2->type, is_init, match_record_field_names) )
					{
					result = false;
					break;
					}
				}
			break;
			}

		case TYPE_LIST:
			{
			const auto& tl1 = t1->AsTypeList()->GetTypes();
			const auto& tl2 = t2->AsTypeList()->GetTypes();

			result = true;

			for ( auto i = 0u; i < tl1.size(); ++i )
				if ( ! same_type(tl1[i], tl2[i], is_init, match_record_field_names) )
					{
					result = false;
					break;
					}
			break;
			}

		case TYPE_VECTOR:
		case TYPE_FILE:
			result = same_type(t1->Yield(), t2->Yield(), is_init, match_record_field_names);
			break;

		case TYPE_TYPE:
			{
			auto tt1 = t1->AsTypeType();
			auto tt2 = t2->AsTypeType();
			result = same_type(tt1->GetType(), tt1->GetType(), is_init, match_record_field_names);
			break;
			}

		default:
			result = false;
		}

	analyzed_types.erase(t1);
	analyzed_types.erase(t2);

	return result;
	}

bool same_attrs(const detail::Attributes* a1, const detail::Attributes* a2)
	{
	if ( ! a1 )
		return (a2 == nullptr);

	if ( ! a2 )
		return (a1 == nullptr);

	return (*a1 == *a2);
	}

bool record_promotion_compatible(const RecordType* super_rec, const RecordType* sub_rec)
	{
	for ( int i = 0; i < sub_rec->NumFields(); ++i )
		{
		int o = super_rec->FieldOffset(sub_rec->FieldName(i));

		if ( o < 0 )
			// Orphaned field.
			continue;

		const auto& sub_field_type = sub_rec->GetFieldType(i);
		const auto& super_field_type = super_rec->GetFieldType(o);

		if ( same_type(sub_field_type, super_field_type) )
			continue;

		if ( sub_field_type->Tag() != TYPE_RECORD )
			return false;

		if ( super_field_type->Tag() != TYPE_RECORD )
			return false;

		if ( ! record_promotion_compatible(super_field_type->AsRecordType(),
		                                   sub_field_type->AsRecordType()) )
			return false;
		}

	return true;
	}

const Type* flatten_type(const Type* t)
	{
	if ( t->Tag() != TYPE_LIST )
		return t;

	const TypeList* tl = t->AsTypeList();

	if ( tl->IsPure() )
		return tl->GetPureType().get();

	const auto& types = tl->GetTypes();

	if ( types.size() == 0 )
		reporter->InternalError("empty type list in flatten_type");

	const auto& ft = types[0];

	if ( types.size() == 1 || tl->AllMatch(ft, false) )
		return ft.get();

	return t;
	}

Type* flatten_type(Type* t)
	{
	return (Type*)flatten_type((const Type*)t);
	}

bool is_assignable(TypeTag t)
	{
	switch ( t )
		{
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_COUNT:
		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_STRING:
		case TYPE_PATTERN:
		case TYPE_ENUM:
		case TYPE_PORT:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_RECORD:
		case TYPE_FUNC:
		case TYPE_ANY:
		case TYPE_ERROR:
		case TYPE_LIST:
			return true;

		case TYPE_VECTOR:
		case TYPE_FILE:
		case TYPE_OPAQUE:
		case TYPE_TABLE:
		case TYPE_TYPE:
			return true;

		case TYPE_VOID:
			return false;
		}

	return false;
	}

#define CHECK_TYPE(t)                                                                              \
	if ( t1 == t || t2 == t )                                                                      \
		return t;

TypeTag max_type(TypeTag t1, TypeTag t2)
	{
	if ( t1 == TYPE_INTERVAL || t1 == TYPE_TIME )
		t1 = TYPE_DOUBLE;
	if ( t2 == TYPE_INTERVAL || t2 == TYPE_TIME )
		t2 = TYPE_DOUBLE;

	if ( BothArithmetic(t1, t2) )
		{
		CHECK_TYPE(TYPE_DOUBLE);
		CHECK_TYPE(TYPE_INT);
		CHECK_TYPE(TYPE_COUNT);

		return TYPE_COUNT;
		}
	else
		{
		reporter->InternalError("non-arithmetic tags in max_type()");
		return TYPE_ERROR;
		}
	}

TypePtr merge_enum_types(const Type* t1, const Type* t2)
	{
	// Could compare pointers t1 == t2, but maybe there's someone out
	// there creating clones of the type, so safer to compare name.
	if ( t1->GetName() != t2->GetName() )
		{
		std::string msg = util::fmt("incompatible enum types: '%s' and '%s'", t1->GetName().data(),
		                            t2->GetName().data());

		t1->Error(msg.data(), t2);
		return nullptr;
		}

	// Doing a lookup here as a roundabout way of ref-ing t1, without
	// changing the function params which has t1 as const and also
	// (potentially) avoiding a pitfall mentioned earlier about clones.
	const auto& id = detail::global_scope()->Find(t1->GetName());

	if ( id && id->IsType() && id->GetType()->Tag() == TYPE_ENUM )
		// It should make most sense to return the real type here rather
		// than a copy since it may be redef'd later in parsing.  If we
		// return a copy, then whoever is using this return value won't
		// actually see those changes from the redef.
		return id->GetType();

	std::string msg = util::fmt("incompatible enum types: '%s' and '%s'"
	                            " ('%s' enum type ID is invalid)",
	                            t1->GetName().data(), t2->GetName().data(), t1->GetName().data());
	t1->Error(msg.data(), t2);
	return nullptr;
	}

TypePtr merge_table_types(const Type* t1, const Type* t2)
	{
	const IndexType* it1 = (const IndexType*)t1;
	const IndexType* it2 = (const IndexType*)t2;

	const auto& tl1 = it1->GetIndexTypes();
	const auto& tl2 = it2->GetIndexTypes();
	TypeListPtr tl3;

	if ( tl1.size() != tl2.size() )
		{
		t1->Error("incompatible types", t2);
		return nullptr;
		}

	tl3 = make_intrusive<TypeList>();

	for ( auto i = 0u; i < tl1.size(); ++i )
		{
		auto tl3_i = merge_types(tl1[i], tl2[i]);
		if ( ! tl3_i )
			return nullptr;

		tl3->Append(std::move(tl3_i));
		}

	const auto& y1 = t1->Yield();
	const auto& y2 = t2->Yield();
	TypePtr y3;

	if ( y1 || y2 )
		{
		if ( ! y1 || ! y2 )
			{
			t1->Error("incompatible types", t2);
			return nullptr;
			}

		y3 = merge_types(y1, y2);
		if ( ! y3 )
			return nullptr;
		}

	if ( t1->IsSet() )
		return make_intrusive<SetType>(std::move(tl3), nullptr);
	else
		return make_intrusive<TableType>(std::move(tl3), std::move(y3));
	}

TypePtr merge_func_types(const Type* t1, const Type* t2)
	{
	if ( ! same_type(t1, t2) )
		{
		t1->Error("incompatible types", t2);
		return nullptr;
		}

	const FuncType* ft1 = (const FuncType*)t1;
	const FuncType* ft2 = (const FuncType*)t1;
	auto args = cast_intrusive<RecordType>(merge_types(ft1->Params(), ft2->Params()));
	auto yield = t1->Yield() ? merge_types(t1->Yield(), t2->Yield()) : nullptr;

	return make_intrusive<FuncType>(std::move(args), std::move(yield), ft1->Flavor());
	}

TypePtr merge_record_types(const Type* t1, const Type* t2)
	{
	const RecordType* rt1 = (const RecordType*)t1;
	const RecordType* rt2 = (const RecordType*)t2;

	// We allow the records to have different numbers of fields.
	// We first go through all of the fields in rt1, and then we
	// check for whether rt2 has any additional fields.

	type_decl_list* tdl3 = new type_decl_list();

	for ( int i = 0; i < rt1->NumFields(); ++i )
		{
		auto td1 = rt1->FieldDecl(i);
		auto td2_offset_i = rt2->FieldOffset(rt1->FieldName(i));

		TypePtr tdl3_i;
		auto attrs3 = make_intrusive<detail::Attributes>(nullptr, true, false);

		if ( td1->attrs )
			attrs3->AddAttrs(td1->attrs);

		if ( td2_offset_i >= 0 )
			{
			auto td2 = rt2->FieldDecl(td2_offset_i);
			tdl3_i = merge_types(td1->type, td2->type);

			if ( td2->attrs )
				attrs3->AddAttrs(td2->attrs);

			if ( ! util::streq(td1->id, td2->id) || ! tdl3_i )
				{
				t1->Error("incompatible record fields", t2);
				delete tdl3;
				return nullptr;
				}
			}
		else
			{
			tdl3_i = td1->type;
			attrs3->AddAttr(make_intrusive<detail::Attr>(detail::ATTR_OPTIONAL));
			}

		if ( attrs3->GetAttrs().empty() )
			attrs3 = nullptr;

		auto td3 = new TypeDecl(util::copy_string(td1->id), std::move(tdl3_i), attrs3);

		tdl3->push_back(td3);
		}

	// Now add in any extras from rt2.
	for ( int i = 0; i < rt2->NumFields(); ++i )
		{
		auto td2 = rt2->FieldDecl(i);
		auto td1_offset_i = rt1->FieldOffset(rt2->FieldName(i));

		if ( td1_offset_i < 0 )
			{
			auto attrs3 = make_intrusive<detail::Attributes>(nullptr, true, false);
			if ( td2->attrs )
				attrs3->AddAttrs(td2->attrs);

			attrs3->AddAttr(make_intrusive<detail::Attr>(detail::ATTR_OPTIONAL));
			auto td_merge = new TypeDecl(util::copy_string(td2->id), std::move(td2->type), attrs3);
			tdl3->push_back(td_merge);
			}
		}

	return make_intrusive<RecordType>(tdl3);
	}

TypePtr merge_list_types(const Type* t1, const Type* t2)
	{
	const TypeList* tl1 = t1->AsTypeList();
	const TypeList* tl2 = t2->AsTypeList();

	if ( tl1->IsPure() != tl2->IsPure() )
		{
		tl1->Error("incompatible lists", tl2);
		return nullptr;
		}

	const auto& l1 = tl1->GetTypes();
	const auto& l2 = tl2->GetTypes();

	if ( l1.size() == 0 || l2.size() == 0 )
		{
		if ( l1.size() == 0 )
			tl1->Error("empty list");
		else
			tl2->Error("empty list");
		return nullptr;
		}

	if ( l1.size() != l2.size() )
		{
		tl1->Error("different number of indices", tl2);
		return nullptr;
		}

	auto tl3 = make_intrusive<TypeList>();

	for ( auto i = 0u; i < l1.size(); ++i )
		tl3->Append(merge_types(l1[i], l2[i]));

	return tl3;
	}

TypePtr merge_types(const TypePtr& arg_t1, const TypePtr& arg_t2)
	{
	auto t1 = arg_t1.get();
	auto t2 = arg_t2.get();
	// t1 = flatten_type(t1);
	// t2 = flatten_type(t2);

	TypeTag tg1 = t1->Tag();
	TypeTag tg2 = t2->Tag();

	if ( BothArithmetic(tg1, tg2) )
		return base_type(max_type(tg1, tg2));

	if ( tg1 != tg2 )
		{
		t1->Error("incompatible types", t2);
		return nullptr;
		}

	switch ( tg1 )
		{
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_STRING:
		case TYPE_PATTERN:
		case TYPE_PORT:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_BOOL:
		case TYPE_ANY:
		case TYPE_ERROR:
			return base_type(tg1);

		case TYPE_ENUM:
			return merge_enum_types(t1, t2);

		case TYPE_TABLE:
			return merge_table_types(t1, t2);

		case TYPE_FUNC:
			return merge_func_types(t1, t2);

		case TYPE_RECORD:
			return merge_record_types(t1, t2);

		case TYPE_LIST:
			return merge_list_types(t1, t2);

		case TYPE_VECTOR:
			if ( ! same_type(t1->Yield(), t2->Yield()) )
				{
				t1->Error("incompatible types", t2);
				return nullptr;
				}

			return make_intrusive<VectorType>(merge_types(t1->Yield(), t2->Yield()));

		case TYPE_FILE:
			if ( ! same_type(t1->Yield(), t2->Yield()) )
				{
				t1->Error("incompatible types", t2);
				return nullptr;
				}

			return make_intrusive<FileType>(merge_types(t1->Yield(), t2->Yield()));

		default:
			reporter->InternalError("bad type in merge_types()");
			return nullptr;
		}
	}

TypePtr merge_type_list(detail::ListExpr* elements)
	{
	TypeList* tl_type = elements->GetType()->AsTypeList();
	const auto& tl = tl_type->GetTypes();

	if ( tl.size() < 1 )
		{
		reporter->Error("no type can be inferred for empty list");
		return nullptr;
		}

	auto t = tl[0];

	if ( tl.size() == 1 )
		return t;

	for ( size_t i = 1; t && i < tl.size(); ++i )
		t = merge_types(t, tl[i]);

	if ( ! t )
		reporter->Error("inconsistent types in list");

	return t;
	}

// Reduces an aggregate type.
static Type* reduce_type(Type* t)
	{
	if ( t->Tag() == TYPE_LIST )
		return flatten_type(t);

	else if ( t->IsSet() )
		{
		const auto& tl = t->AsTableType()->GetIndices();

		if ( tl->GetTypes().size() == 1 )
			return tl->GetTypes()[0].get();
		else
			return tl.get();
		}

	else
		return t;
	}

static TableTypePtr init_table_type(detail::ListExpr* l)
	{
	auto& elems = l->Exprs();
	TypePtr index;
	TypePtr yield;

	for ( auto e : elems )
		{
		if ( e->Tag() != detail::EXPR_ASSIGN )
			{
			e->Error("table constructor element lacks '=' structure");
			return nullptr;
			}

		auto& ind = e->GetOp1()->GetType();
		auto& y = e->GetOp2()->GetType();

		if ( ! index )
			{
			index = ind;
			yield = y;
			continue;
			}

		index = merge_types(index, ind);
		yield = merge_types(yield, y);

		if ( ! index || ! yield )
			// Error message already generated.
			return nullptr;
		}

	if ( index->Tag() != TYPE_LIST )
		return nullptr;

	return make_intrusive<TableType>(cast_intrusive<TypeList>(index), yield);
	}

static SetTypePtr init_set_type(detail::ListExpr* l)
	{
	auto& elems = l->Exprs();
	TypePtr index;

	for ( auto e : elems )
		{
		auto& ind = e->GetType();

		if ( ! index )
			{
			index = ind;
			continue;
			}

		index = merge_types(index, ind);

		if ( ! index )
			return nullptr;
		}

	TypeListPtr ind_list;

	if ( index->Tag() == TYPE_LIST )
		ind_list = cast_intrusive<TypeList>(index);
	else
		{
		ind_list = make_intrusive<TypeList>(index);
		ind_list->Append(index);
		}

	return make_intrusive<SetType>(ind_list, nullptr);
	}

TypePtr init_type(const detail::ExprPtr& init)
	{
	if ( init->Tag() != detail::EXPR_LIST )
		{
		auto t = init->InitType();

		if ( (t->Tag() == TYPE_TABLE && cast_intrusive<TableType>(t)->IsUnspecifiedTable()) ||
		     (t->Tag() == TYPE_VECTOR && cast_intrusive<VectorType>(t)->IsUnspecifiedVector()) )
			{
			init->Error("empty constructor in untyped initialization");
			return nullptr;
			}

		return t;
		}

	auto init_list = init->AsListExpr();
	const auto& el = init_list->Exprs();

	if ( el.length() == 0 )
		{
		init->Error("empty list in untyped initialization");
		return nullptr;
		}

	// Could be a record, a set, or a list of table elements.
	auto e0 = el[0];

	if ( e0->IsRecordElement(nullptr) )
		// ListExpr's know how to build a record from their components.
		return init_list->InitType();

	if ( e0->Tag() == detail::EXPR_ASSIGN )
		return init_table_type(init_list);
	else
		return init_set_type(init_list);
	}

bool is_atomic_type(const Type& t)
	{
	switch ( t.InternalType() )
		{
		case TYPE_INTERNAL_INT:
		case TYPE_INTERNAL_UNSIGNED:
		case TYPE_INTERNAL_DOUBLE:
		case TYPE_INTERNAL_STRING:
		case TYPE_INTERNAL_ADDR:
		case TYPE_INTERNAL_SUBNET:
			return true;
		default:
			return false;
		}
	}

const TypePtr& base_type(TypeTag tag)
	{
	static TypePtr base_types[NUM_TYPES];

	// We could check here that "tag" actually corresponds to a basic type.
	if ( ! base_types[tag] )
		{
		base_types[tag] = make_intrusive<Type>(tag, true);
		// Give the base types a pseudo-location for easier identification.
		detail::Location l(type_name(tag), 0, 0, 0, 0);
		base_types[tag]->SetLocationInfo(&l);
		}

	return base_types[tag];
	}

	} // namespace zeek
