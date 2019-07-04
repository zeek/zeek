// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Type.h"
#include "Attr.h"
#include "Expr.h"
#include "Scope.h"
#include "Func.h"
#include "Reporter.h"
#include "zeekygen/Manager.h"
#include "zeekygen/utils.h"

#include <string>
#include <list>
#include <map>

BroType::TypeAliasMap BroType::type_aliases;

// Note: This function must be thread-safe.
const char* type_name(TypeTag t)
	{
	static const char* type_names[int(NUM_TYPES)] = {
		"void",      // 0
		"bool",      // 1
		"int",       // 2
		"count",     // 3
		"counter",   // 4
		"double",    // 5
		"time",      // 6
		"interval",  // 7
		"string",    // 8
		"pattern",   // 9
		"enum",      // 10
		"timer",     // 11
		"port",      // 12
		"addr",      // 13
		"subnet",    // 14
		"any",       // 15
		"table",     // 16
		"union",     // 17
		"record",    // 18
		"types",     // 19
		"func",      // 20
		"file",      // 21
		"vector",    // 22
		"opaque",    // 23
		"type",      // 24
		"error",     // 25
	};

	if ( int(t) >= NUM_TYPES )
		return "type_name(): not a type tag";

	return type_names[int(t)];
	}

BroType::BroType(TypeTag t, bool arg_base_type)
	{
	tag = t;
	is_network_order = 0;
	base_type = arg_base_type;

	switch ( tag ) {
	case TYPE_VOID:
		internal_tag = TYPE_INTERNAL_VOID;
		break;

	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_ENUM:
		internal_tag = TYPE_INTERNAL_INT;
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		internal_tag = TYPE_INTERNAL_UNSIGNED;
		break;

	case TYPE_PORT:
		internal_tag = TYPE_INTERNAL_UNSIGNED;
		is_network_order = 1;
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		internal_tag = TYPE_INTERNAL_DOUBLE;
		break;

	case TYPE_STRING:
		internal_tag = TYPE_INTERNAL_STRING;
		break;

	case TYPE_ADDR:
		internal_tag = TYPE_INTERNAL_ADDR;
		break;

	case TYPE_SUBNET:
		internal_tag = TYPE_INTERNAL_SUBNET;
		break;

	case TYPE_PATTERN:
	case TYPE_TIMER:
	case TYPE_ANY:
	case TYPE_TABLE:
	case TYPE_UNION:
	case TYPE_RECORD:
	case TYPE_LIST:
	case TYPE_FUNC:
	case TYPE_FILE:
	case TYPE_OPAQUE:
	case TYPE_VECTOR:
	case TYPE_TYPE:
		internal_tag = TYPE_INTERNAL_OTHER;
		break;

	case TYPE_ERROR:
		internal_tag = TYPE_INTERNAL_ERROR;
		break;
	}

	}

BroType* BroType::ShallowClone()
	{
	switch ( tag ) {
		case TYPE_VOID:
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_COUNT:
		case TYPE_COUNTER:
		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_STRING:
		case TYPE_PATTERN:
		case TYPE_TIMER:
		case TYPE_PORT:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_ANY:
			return new BroType(tag, base_type);

		default:
			reporter->InternalError("cloning illegal base BroType");
	}
	return nullptr;
	}

int BroType::MatchesIndex(ListExpr*& index) const
	{
	if ( Tag() == TYPE_STRING )
		{
		if ( index->Exprs().length() != 1 && index->Exprs().length() != 2 )
			return DOES_NOT_MATCH_INDEX;

		if ( check_and_promote_exprs_to_type(index, ::base_type(TYPE_INT)) )
			return MATCHES_INDEX_SCALAR;
		}

	return DOES_NOT_MATCH_INDEX;
	}

BroType* BroType::YieldType()
	{
	return 0;
	}

int BroType::HasField(const char* /* field */) const
	{
	return 0;
	}

BroType* BroType::FieldType(const char* /* field */) const
	{
	return 0;
	}

void BroType::Describe(ODesc* d) const
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

void BroType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(fmt(":zeek:type:`%s`", type_name(Tag())));
	}

void BroType::SetError()
	{
	tag = TYPE_ERROR;
	}

unsigned int BroType::MemoryAllocation() const
	{
	return padded_sizeof(*this);
	}

TypeList::~TypeList()
	{
	for ( const auto& type : types )
		Unref(type);

	Unref(pure_type);
	}

int TypeList::AllMatch(const BroType* t, int is_init) const
	{
	for ( const auto& type : types )
		if ( ! same_type(type, t, is_init) )
			return 0;
	return 1;
	}

void TypeList::Append(BroType* t)
	{
	if ( pure_type && ! same_type(t, pure_type) )
		reporter->InternalError("pure type-list violation");

	types.push_back(t);
	}

void TypeList::AppendEvenIfNotPure(BroType* t)
	{
	if ( pure_type && ! same_type(t, pure_type) )
		{
		Unref(pure_type);
		pure_type = 0;
		}

	types.push_back(t);
	}

void TypeList::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("list of");
	else
		{
		d->Add(int(Tag()));
		d->Add(IsPure());
		if ( IsPure() )
			pure_type->Describe(d);
		d->Add(types.length());
		}

	if ( IsPure() )
		pure_type->Describe(d);
	else
		{
		loop_over_list(types, i)
			{
			if ( i > 0 && ! d->IsBinary() )
				d->Add(",");

			types[i]->Describe(d);
			}
		}
	}

IndexType::~IndexType()
	{
	Unref(indices);
	Unref(yield_type);
	}

int IndexType::MatchesIndex(ListExpr*& index) const
	{
	// If we have a type indexed by subnets, addresses are ok.
	const type_list* types = indices->Types();
	const expr_list& exprs = index->Exprs();

	if ( types->length() == 1 && (*types)[0]->Tag() == TYPE_SUBNET &&
	     exprs.length() == 1 && exprs[0]->Type()->Tag() == TYPE_ADDR )
		return MATCHES_INDEX_SCALAR;

	return check_and_promote_exprs(index, Indices()) ?
			MATCHES_INDEX_SCALAR : DOES_NOT_MATCH_INDEX;
	}

BroType* IndexType::YieldType()
	{
	return yield_type;
	}

const BroType* IndexType::YieldType() const
	{
	return yield_type;
	}

void IndexType::Describe(ODesc* d) const
	{
	BroType::Describe(d);
	if ( ! d->IsBinary() )
		d->Add("[");
	loop_over_list(*IndexTypes(), i)
		{
		if ( ! d->IsBinary() && i > 0 )
			d->Add(",");
		(*IndexTypes())[i]->Describe(d);
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

	loop_over_list(*IndexTypes(), i)
		{
		if ( i > 0 )
			d->Add(", ");

		const BroType* t = (*IndexTypes())[i];

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
	const type_list* types = indices->Types();
	if ( types->length() == 1 && (*types)[0]->Tag() == TYPE_SUBNET )
		return true;
	return false;
	}

TableType::TableType(TypeList* ind, BroType* yield)
: IndexType(TYPE_TABLE, ind, yield)
	{
	if ( ! indices )
		return;

	type_list* tl = indices->Types();

	for ( const auto& tli : *tl )
		{
		InternalTypeTag t = tli->InternalType();

		if ( t == TYPE_INTERNAL_ERROR )
			break;

		// Allow functions, since they can be compared
		// for Func* pointer equality.
		if ( t == TYPE_INTERNAL_OTHER && tli->Tag() != TYPE_FUNC &&
		     tli->Tag() != TYPE_RECORD )
			{
			tli->Error("bad index type");
			SetError();
			break;
			}
		}
	}

TableType* TableType::ShallowClone()
	{
	if ( indices )
		indices->Ref();
	if ( yield_type )
		yield_type->Ref();

	return new TableType(indices, yield_type);
	}

bool TableType::IsUnspecifiedTable() const
	{
	// Unspecified types have an empty list of indices.
	return indices->Types()->length() == 0;
	}

TypeList* TableType::ExpandRecordIndex(RecordType* rt) const
	{
	TypeList* tl = new TypeList();

	int n = rt->NumFields();
	for ( int i = 0; i < n; ++i )
		{
		TypeDecl* td = rt->FieldDecl(i);
		tl->Append(td->type->Ref());
		}

	return tl;
	}

SetType::SetType(TypeList* ind, ListExpr* arg_elements) : TableType(ind, 0)
	{
	elements = arg_elements;
	if ( elements )
		{
		if ( indices )
			{ // We already have a type.
			if ( ! check_and_promote_exprs(elements, indices) )
				SetError();
			}
		else
			{
			TypeList* tl_type = elements->Type()->AsTypeList();
			type_list* tl = tl_type->Types();

			if ( tl->length() < 1 )
				{
				Error("no type given for set");
				SetError();
				}

			else if ( tl->length() == 1 )
				{
				BroType* t = flatten_type((*tl)[0]->Ref());
				indices = new TypeList(t);
				indices->Append(t->Ref());
				}

			else
				{
				BroType* t = merge_types((*tl)[0], (*tl)[1]);

				for ( int i = 2; t && i < tl->length(); ++i )
					{
					BroType* t_new =
						merge_types(t, (*tl)[i]);
					Unref(t);
					t = t_new;
					}

				if ( ! t )
					{
					Error("bad set type");
					return;
					}

				indices = new TypeList(t);
				indices->Append(t);
				}
			}
		}
	}

SetType* SetType::ShallowClone()
	{
	// constructor only consumes indices when elements
	// is set
	if ( elements && indices )
		{
		elements->Ref();
		indices->Ref();
		}

	return new SetType(indices, elements);
	}

SetType::~SetType()
	{
	Unref(elements);
	}

FuncType::FuncType(RecordType* arg_args, BroType* arg_yield, function_flavor arg_flavor)
: BroType(TYPE_FUNC)
	{
	yield = arg_yield;
	flavor = arg_flavor;
	AddOverload(arg_args);
	}

int FuncType::AddOverload(RecordType* args)
	{
	auto odecl = new FuncDecl();
	odecl->args = args;
	odecl->arg_types = new TypeList();

	bool has_default_arg = false;
	auto added = true;

	for ( int i = 0; i < args->NumFields(); ++i )
		{
		const TypeDecl* td = args->FieldDecl(i);

		if ( td->FindAttr(ATTR_DEFAULT) )
			has_default_arg = true;

		else if ( has_default_arg )
			{
			std::string err_str = fmt("required parameter '%s' must precede "
			                          "default parameters", td->id);
			args->Error(err_str.data());
			added = false;
			}

		odecl->arg_types->Append(args->FieldType(i)->Ref());
		}

	// Check that adding this overload doesn't create ambiguity with others
	for ( auto& o : overloads )
		{
		// We need to find at least one differing parameter, and if we
		// don't have a differing parameter before we run into a &default,
		// then it's ambiguous.

		auto have_unique_param = false;
		RecordType* more_args;
		RecordType* less_args;

		if ( o->decl->args->NumFields() > args->NumFields() )
			{
			more_args = o->decl->args;
			less_args = args;
			}
		else
			{
			more_args = args;
			less_args = o->decl->args;
			}

		for ( auto i = 0; i < more_args->NumFields(); ++i )
			{
			if ( more_args->FieldDecl(i)->FindAttr(ATTR_DEFAULT) )
				break;

			if ( i == less_args->NumFields() )
				{
				have_unique_param = true;
				break;
				}

			if ( less_args->FieldDecl(i)->FindAttr(ATTR_DEFAULT) )
				break;

			if ( ! same_type(less_args->FieldType(i),
			                 more_args->FieldType(i), false, false) )
				{
				have_unique_param = true;
				break;
				}
			}

		if ( ! have_unique_param )
			{
			args->Error("function parameters would create ambiguous overload",
			            o->decl->args);
			added = false;
			}
		}

	auto rval = -1;

	if ( added )
		{
		rval = overloads.size();
		auto o = new FuncOverload();
		o->index = rval;
		o->type = this;
		o->decl = odecl;
		o->impl = nullptr;
		overloads.emplace_back(o);
		}
	else
		{
		Unref(odecl->args);
		Unref(odecl->arg_types);
		delete odecl;
		}

	return rval;
	}

int FuncType::GetOverloadIndex(RecordType* matching_args)
	{
	for ( auto i = 0u; i < overloads.size(); ++i )
		if ( same_type(overloads[i]->decl->args, matching_args, false, false) )
			return i;

	return -1;
	}

FuncOverload* FuncType::GetOverload(RecordType* matching_args)
	{
	auto idx = GetOverloadIndex(matching_args);
	return GetOverload(idx);
	}

FuncOverload* FuncType::GetOverload(int idx)
	{
	if ( idx < 0 )
		return nullptr;

	return overloads[idx];
	}

FuncType* FuncType::ShallowClone()
	{
	auto f = new FuncType();
	f->yield = yield->Ref();
	f->flavor = flavor;

	for ( auto& o : overloads )
		{
		auto co = new FuncOverload();
		auto codecl = new FuncDecl();
		co->index = o->index;
		co->type = f;
		co->decl->args = o->decl->args->Ref()->AsRecordType();
		co->decl->arg_types = o->decl->arg_types->Ref()->AsTypeList();

		co->impl = o->impl;
		::Ref(co->impl);

		f->overloads.emplace_back(co);
		}

	return f;
	}

string FuncType::FlavorString() const
	{
	switch ( flavor ) {

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

FuncType::~FuncType()
	{
	for ( auto& o : overloads )
		{
		Unref(o->decl->args);
		Unref(o->decl->arg_types);
		delete o->decl;
		Unref(o->impl);
		delete o;
		}

	Unref(yield);
	}

BroType* FuncType::YieldType()
	{
	return yield;
	}

const BroType* FuncType::YieldType() const
	{
	return yield;
	}

int FuncType::MatchesIndex(ListExpr*& index) const
	{
	if ( overloads.size() == 1 )
		return check_and_promote_args(index, overloads[0]->decl->args) ?
		           MATCHES_INDEX_SCALAR : DOES_NOT_MATCH_INDEX;

	for ( auto& o : overloads )
		{
		expr_list& el = index->Exprs();

		if ( el.length() > o->decl->args->NumFields() )
			continue;

		auto match = true;

		for ( auto i = 0; i < o->decl->args->NumFields(); ++i )
			{
			if ( i == el.length() )
				{
				// This overload can now only match if this param has &default
				// (implies any subsequent params also have a &default)
				match = o->decl->args->FieldDecl(i)->FindAttr(ATTR_DEFAULT);
				break;
				}

			if ( ! same_type(el[i]->Type(), o->decl->args->FieldType(i)) )
				{
				match = false;
				break;
				}
			}

		if ( match )
			return check_and_promote_args(index, o->decl->args) ?
			           MATCHES_INDEX_SCALAR : DOES_NOT_MATCH_INDEX;
		}

	return DOES_NOT_MATCH_INDEX;
	}

int FuncType::CheckArgs(const type_list* args, bool is_init) const
	{
	// TODO: implement for overloads
	assert(overloads.size() == 1);
	auto arg_types = overloads[0]->decl->arg_types;

	const type_list* my_args = arg_types->Types();

	if ( my_args->length() != args->length() )
		{
		Warn(fmt("Wrong number of arguments for function. Expected %d, got %d.",
			args->length(), my_args->length()));
		return 0;
		}

	int success = 1;

	for ( int i = 0; i < my_args->length(); ++i )
		if ( ! same_type((*args)[i], (*my_args)[i], is_init) )
			{
			Warn(fmt("Type mismatch in function argument #%d. Expected %s, got %s.",
				i, type_name((*args)[i]->Tag()), type_name((*my_args)[i]->Tag())));
			success = 0;
			}

	return success;
	}

RecordType* FuncType::Args() const
	{
	// TODO: audit usages
	assert(overloads.size() == 1);
	return overloads[0]->decl->args;
	}

TypeList* FuncType::ArgTypes() const
	{
	// TODO: audit usages
	assert(overloads.size() == 1);
	return overloads[0]->decl->arg_types;
	}

void FuncType::Describe(ODesc* d) const
	{
	// TODO: implement for overloads
	assert(overloads.size() == 1);
	auto args = overloads[0]->decl->args;

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
		d->Add(yield != 0);
		args->DescribeFields(d);
		if ( yield )
			yield->Describe(d);
		}
	}

void FuncType::DescribeReST(ODesc* d, bool roles_only) const
	{
	// TODO: implement for overloads
	assert(overloads.size() == 1);
	auto args = overloads[0]->decl->args;

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

TypeDecl::TypeDecl(BroType* t, const char* i, attr_list* arg_attrs, bool in_record)
	{
	type = t;
	attrs = arg_attrs ? new Attributes(arg_attrs, t, in_record, false) : 0;
	id = i;
	}

TypeDecl::TypeDecl(const TypeDecl& other)
	{
	type = other.type->Ref();
	attrs = other.attrs;

	if ( attrs )
		::Ref(attrs);

	id = copy_string(other.id);
	}

TypeDecl::~TypeDecl()
	{
	Unref(type);
	Unref(attrs);
	delete [] id;
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

RecordType::RecordType(type_decl_list* arg_types) : BroType(TYPE_RECORD)
	{
	types = arg_types;
	num_fields = types ? types->length() : 0;
	}

// in this case the clone is actually not so shallow, since
// it gets modified by everyone.
RecordType* RecordType::ShallowClone()
	{
	auto pass = new type_decl_list();
	for ( const auto& type : *types )
		pass->push_back(new TypeDecl(*type));
	return new RecordType(pass);
	}

RecordType::~RecordType()
	{
	if ( types )
		{
		for ( auto type : *types )
			delete type;

		delete types;
		}
	}

int RecordType::HasField(const char* field) const
	{
	return FieldOffset(field) >= 0;
	}

BroType* RecordType::FieldType(const char* field) const
	{
	int offset = FieldOffset(field);
	return offset >= 0 ? FieldType(offset) : 0;
	}

BroType* RecordType::FieldType(int field) const
	{
	return (*types)[field]->type;
	}

Val* RecordType::FieldDefault(int field) const
	{
	const TypeDecl* td = FieldDecl(field);

	if ( ! td->attrs )
		return 0;

	const Attr* def_attr = td->attrs->FindAttr(ATTR_DEFAULT);

	return def_attr ? def_attr->AttrExpr()->Eval(0) : 0;
	}

int RecordType::FieldOffset(const char* field) const
	{
	loop_over_list(*types, i)
		{
		TypeDecl* td = (*types)[i];
		if ( streq(td->id, field) )
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

void RecordType::Describe(ODesc* d) const
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

static string container_type_name(const BroType* ft)
	{
	string s;
	if ( ft->Tag() == TYPE_RECORD )
		s = "record " + ft->GetName();
	else if ( ft->Tag() == TYPE_VECTOR )
		s = "vector of " + container_type_name(ft->YieldType());
	else if ( ft->Tag() == TYPE_TABLE )
		{
		if ( ft->IsSet() )
			s = "set[";
		else
			s = "table[";
		const type_list* tl = ((const IndexType*) ft)->IndexTypes();
		loop_over_list(*tl, i)
			{
			if ( i > 0 )
				s += ",";
			s += container_type_name((*tl)[i]);
			}
		s += "]";
		if ( ft->YieldType() )
			{
			s += " of ";
			s += container_type_name(ft->YieldType());
			}
		}
	else
		s = type_name(ft->Tag());
	return s;
	}

TableVal* RecordType::GetRecordFieldsVal(const RecordVal* rv) const
	{
	auto rval = new TableVal(internal_type("record_field_table")->AsTableType());

	for ( int i = 0; i < NumFields(); ++i )
		{
		const BroType* ft = FieldType(i);
		const TypeDecl* fd = FieldDecl(i);
		Val* fv = nullptr;

		if ( rv )
			fv = rv->Lookup(i);

		if ( fv )
			::Ref(fv);

		bool logged = (fd->attrs && fd->FindAttr(ATTR_LOG) != 0);

		RecordVal* nr = new RecordVal(internal_type("record_field")->AsRecordType());

		string s = container_type_name(ft);
		nr->Assign(0, new StringVal(s));
		nr->Assign(1, val_mgr->GetBool(logged));
		nr->Assign(2, fv);
		nr->Assign(3, FieldDefault(i));
		Val* field_name = new StringVal(FieldName(i));
		rval->Assign(field_name, nr);
		Unref(field_name);
		}

	return rval;
	}

const char* RecordType::AddFields(type_decl_list* others, attr_list* attr)
	{
	assert(types);

	bool log = false;

	if ( attr )
		{
		for ( const auto& at : *attr )
			{
			if ( at->Tag() == ATTR_LOG )
				log = true;
			}
		}

	for ( const auto& td : *others )
		{
		if ( ! td->FindAttr(ATTR_DEFAULT) &&
		     ! td->FindAttr(ATTR_OPTIONAL) )
			return "extension field must be &optional or have &default";

		if ( log )
			{
			if ( ! td->attrs )
				td->attrs = new Attributes(new attr_list, td->type, true, false);

			td->attrs->AddAttr(new Attr(ATTR_LOG));
			}

		types->push_back(td);
		}

	delete others;

	num_fields = types->length();
	return 0;
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

			if ( d->FindType(td->type) )
				d->Add("<recursion>");
			else
				td->type->Describe(d);

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
				type->type->Describe(d);
				d->SP();
				d->Add(type->id);
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

		if ( d->FindType(td->type) )
			d->Add("<recursion>");
		else
			{
			if ( num_fields == 1 && streq(td->id, "va_args") &&
			     td->type->Tag() == TYPE_ANY )
				// This was a BIF using variable argument list
				d->Add("...");
			else
				td->DescribeReST(d);
			}

		if ( func_args )
			continue;

		using zeekygen::IdentifierInfo;
		IdentifierInfo* doc = zeekygen_mgr->GetIdentifierInfo(GetName());

		if ( ! doc )
			{
			reporter->InternalWarning("Failed to lookup record doc: %s",
			                          GetName().c_str());
			continue;
			}

		string field_from_script = doc->GetDeclaringScriptForField(td->id);
		string type_from_script;

		if ( doc->GetDeclaringScript() )
			type_from_script = doc->GetDeclaringScript()->Name();

		if ( ! field_from_script.empty() &&
		     field_from_script != type_from_script )
			{
			d->PushIndent();
			d->Add(zeekygen::redef_indication(field_from_script).c_str());
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

				if ( zeekygen::prettify_params(s) )
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
	if ( decl)
		{
		string result;
		if ( const Attr* deprecation = decl->FindAttr(ATTR_DEPRECATED) )
			{
			ConstExpr* expr = static_cast<ConstExpr*>(deprecation->AttrExpr());
			if ( expr )
				{
				StringVal* text = expr->Value()->AsStringVal();
				result = text->CheckString();
				}
			}

		if ( result.empty() )
			return fmt("deprecated (%s%s$%s)", GetName().c_str(), has_check ? "?" : "",
				FieldName(field));
		else
			return fmt("deprecated (%s%s$%s): %s", GetName().c_str(), has_check ? "?" : "",
				FieldName(field), result.c_str());
		}

	return "";
	}

SubNetType::SubNetType() : BroType(TYPE_SUBNET)
	{
	}

void SubNetType::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->Add("subnet");
	else
		d->Add(int(Tag()));
	}

FileType::FileType(BroType* yield_type)
: BroType(TYPE_FILE)
	{
	yield = yield_type;
	}

FileType::~FileType()
	{
	Unref(yield);
	}

BroType* FileType::YieldType()
	{
	return yield;
	}

void FileType::Describe(ODesc* d) const
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

OpaqueType::OpaqueType(const string& arg_name) : BroType(TYPE_OPAQUE)
	{
	name = arg_name;
	}

void OpaqueType::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("opaque of");
	else
		d->Add(int(Tag()));

	d->Add(name.c_str());
	}

void OpaqueType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(fmt(":zeek:type:`%s` of %s", type_name(Tag()), name.c_str()));
	}

EnumType::EnumType(const string& name)
	: BroType(TYPE_ENUM)
	{
	counter = 0;
	SetName(name);
	}

EnumType::EnumType(const EnumType* e)
	: BroType(TYPE_ENUM)
	{
	counter = e->counter;
	SetName(e->GetName());

	for ( auto it = e->names.begin(); it != e->names.end(); ++it )
		names[it->first] = it->second;

	vals = e->vals;

	for ( auto& kv : vals )
		::Ref(kv.second);
	}

EnumType* EnumType::ShallowClone()
	{
	if ( counter == 0 )
		return new EnumType(GetName());

	return new EnumType(this);
	}

EnumType::~EnumType()
	{
	for ( auto& kv : vals )
		Unref(kv.second);
	}

// Note, we use reporter->Error() here (not Error()) to include the current script
// location in the error message, rather than the one where the type was
// originally defined.
void EnumType::AddName(const string& module_name, const char* name, bool is_export, Expr* deprecation)
	{
	/* implicit, auto-increment */
	if ( counter < 0)
		{
		reporter->Error("cannot mix explicit enumerator assignment and implicit auto-increment");
		SetError();
		return;
		}
	CheckAndAddName(module_name, name, counter, is_export, deprecation);
	counter++;
	}

void EnumType::AddName(const string& module_name, const char* name, bro_int_t val, bool is_export, Expr* deprecation)
	{
	/* explicit value specified */
	if ( counter > 0 )
		{
		reporter->Error("cannot mix explicit enumerator assignment and implicit auto-increment");
		SetError();
		return;
		}
	counter = -1;
	CheckAndAddName(module_name, name, val, is_export, deprecation);
	}

void EnumType::CheckAndAddName(const string& module_name, const char* name,
                               bro_int_t val, bool is_export, Expr* deprecation)
	{
	if ( Lookup(val) )
		{
		reporter->Error("enumerator value in enumerated type definition already exists");
		SetError();
		return;
		}

	ID* id = lookup_ID(name, module_name.c_str());

	if ( ! id )
		{
		id = install_ID(name, module_name.c_str(), true, is_export);
		id->SetType(this->Ref());
		id->SetEnumConst();

		if ( deprecation )
			id->MakeDeprecated(deprecation);

		zeekygen_mgr->Identifier(id);
		}
	else
		{
		// We allow double-definitions if matching exactly. This is so that
		// we can define an enum both in a *.bif and *.zeek for avoiding
		// cyclic dependencies.
		string fullname = make_full_var_name(module_name.c_str(), name);
		if ( id->Name() != fullname
		     || (id->HasVal() && val != id->ID_Val()->AsEnum())
		     || (names.find(fullname) != names.end() && names[fullname] != val) )
			{
			Unref(id);
			reporter->Error("identifier or enumerator value in enumerated type definition already exists");
			SetError();
			return;
			}

		Unref(id);
		}

	AddNameInternal(module_name, name, val, is_export);

	if ( vals.find(val) == vals.end() )
		vals[val] = new EnumVal(this, val);

	set<BroType*> types = BroType::GetAliases(GetName());
	set<BroType*>::const_iterator it;

	for ( it = types.begin(); it != types.end(); ++it )
		if ( *it != this )
			(*it)->AsEnumType()->AddNameInternal(module_name, name, val,
							     is_export);
	}

void EnumType::AddNameInternal(const string& module_name, const char* name,
                               bro_int_t val, bool is_export)
	{
	string fullname = make_full_var_name(module_name.c_str(), name);
	names[fullname] = val;
	}

bro_int_t EnumType::Lookup(const string& module_name, const char* name) const
	{
	NameMap::const_iterator pos =
		names.find(make_full_var_name(module_name.c_str(), name).c_str());

	if ( pos == names.end() )
		return -1;
	else
		return pos->second;
	}

const char* EnumType::Lookup(bro_int_t value) const
	{
	for ( NameMap::const_iterator iter = names.begin();
	      iter != names.end(); ++iter )
		if ( iter->second == value )
			return iter->first.c_str();

	return 0;
	}

EnumType::enum_name_list EnumType::Names() const
	{
	enum_name_list n;
	for ( NameMap::const_iterator iter = names.begin();
	      iter != names.end(); ++iter )
		n.push_back(std::make_pair(iter->first, iter->second));

	return n;
	}

EnumVal* EnumType::GetVal(bro_int_t i)
	{
	auto it = vals.find(i);
	EnumVal* rval;

	if ( it == vals.end() )
		{
		rval = new EnumVal(this, i);
		vals[i] = rval;
		}
	else
		rval = it->second;

	::Ref(rval);
	return rval;
	}

void EnumType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(":zeek:type:`enum`");

	// Create temporary, reverse name map so that enums can be documented
	// in ascending order of their actual integral value instead of by name.
	typedef map<bro_int_t, std::string> RevNameMap;

	RevNameMap rev;

	for ( NameMap::const_iterator it = names.begin(); it != names.end(); ++it )
		rev[it->second] = it->first;

	for ( RevNameMap::const_iterator it = rev.begin(); it != rev.end(); ++it )
		{
		d->NL();
		d->PushIndent();

		if ( roles_only )
			d->Add(fmt(":zeek:enum:`%s`", it->second.c_str()));
		else
			d->Add(fmt(".. zeek:enum:: %s %s", it->second.c_str(), GetName().c_str()));

		using zeekygen::IdentifierInfo;
		IdentifierInfo* doc = zeekygen_mgr->GetIdentifierInfo(it->second);

		if ( ! doc )
			{
			reporter->InternalWarning("Enum %s documentation lookup failure",
			                          it->second.c_str());
			continue;
			}

		string enum_from_script;
		string type_from_script;

		if ( doc->GetDeclaringScript() )
			enum_from_script = doc->GetDeclaringScript()->Name();

		IdentifierInfo* type_doc = zeekygen_mgr->GetIdentifierInfo(GetName());

		if ( type_doc && type_doc->GetDeclaringScript() )
			type_from_script = type_doc->GetDeclaringScript()->Name();

		if ( ! enum_from_script.empty() &&
		     enum_from_script != type_from_script )
			{
			d->NL();
			d->PushIndent();
			d->Add(zeekygen::redef_indication(enum_from_script).c_str());
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

VectorType::VectorType(BroType* element_type)
    : BroType(TYPE_VECTOR), yield_type(element_type)
	{
	}

VectorType* VectorType::ShallowClone()
	{
	return new VectorType(yield_type);
	}

VectorType::~VectorType()
	{
	Unref(yield_type);
	}

BroType* VectorType::YieldType()
	{
	// Work around the fact that we use void internally to mark a vector
	// as being unspecified. When looking at its yield type, we need to
	// return any as that's what other code historically expects for type
	// comparisions.
	if ( IsUnspecifiedVector() )
		{
		BroType* ret = ::base_type(TYPE_ANY);
		Unref(ret); // unref, because this won't be held by anyone.
		assert(ret);
		return ret;
		}

	return yield_type;
	}

const BroType* VectorType::YieldType() const
	{
	// Work around the fact that we use void internally to mark a vector
	// as being unspecified. When looking at its yield type, we need to
	// return any as that's what other code historically expects for type
	// comparisions.
	if ( IsUnspecifiedVector() )
		{
		BroType* ret = ::base_type(TYPE_ANY);
		Unref(ret); // unref, because this won't be held by anyone.
		assert(ret);
		return ret;
		}

	return yield_type;
	}

int VectorType::MatchesIndex(ListExpr*& index) const
	{
	expr_list& el = index->Exprs();

	if ( el.length() != 1 && el.length() != 2)
		return DOES_NOT_MATCH_INDEX;

	if ( el.length() == 2 )
		return MATCHES_INDEX_VECTOR;
	else if ( el[0]->Type()->Tag() == TYPE_VECTOR )
		return (IsIntegral(el[0]->Type()->YieldType()->Tag()) ||
			 IsBool(el[0]->Type()->YieldType()->Tag())) ?
				MATCHES_INDEX_VECTOR : DOES_NOT_MATCH_INDEX;
	else
		return (IsIntegral(el[0]->Type()->Tag()) ||
			 IsBool(el[0]->Type()->Tag())) ?
				MATCHES_INDEX_SCALAR : DOES_NOT_MATCH_INDEX;
	}

bool VectorType::IsUnspecifiedVector() const
	{
	return yield_type->Tag() == TYPE_VOID;
	}

void VectorType::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		d->AddSP("vector of");
	else
		d->Add(int(Tag()));

	yield_type->Describe(d);
	}

void VectorType::DescribeReST(ODesc* d, bool roles_only) const
	{
	d->Add(fmt(":zeek:type:`%s` of ", type_name(Tag())));

	if ( yield_type->GetName().empty() )
		yield_type->DescribeReST(d, roles_only);
	else
		d->Add(fmt(":zeek:type:`%s`", yield_type->GetName().c_str()));
	}

BroType* base_type_no_ref(TypeTag tag)
	{
	static BroType* base_types[NUM_TYPES];

	// We could check here that "tag" actually corresponds to a BRO
	// basic type.

	int t = int(tag);
	if ( ! base_types[t] )
		{
		base_types[t] = new BroType(tag, true);
		// Give the base types a pseudo-location for easier identification.
		Location l(type_name(tag), 0, 0, 0, 0);
		base_types[t]->SetLocationInfo(&l);
		}

	return base_types[t];
	}


// Returns true if t1 is initialization-compatible with t2 (i.e., if an
// initializer with type t1 can be used to initialize a value with type t2),
// false otherwise.  Assumes that t1's tag is different from t2's.  Note
// that the test is in only one direction - we don't check whether t2 is
// initialization-compatible with t1.
static int is_init_compat(const BroType* t1, const BroType* t2)
	{
	if ( t1->Tag() == TYPE_LIST )
		{
		if ( t2->Tag() == TYPE_RECORD )
			return 1;
		else
			return t1->AsTypeList()->AllMatch(t2, 1);
		}

	if ( t1->IsSet() )
		return same_type(t1->AsSetType()->Indices(), t2, 1);

	return 0;
	}

int same_type(const BroType* t1, const BroType* t2, int is_init, bool match_record_field_names)
	{
	if ( t1 == t2 ||
	     t1->Tag() == TYPE_ANY ||
	     t2->Tag() == TYPE_ANY )
		return 1;

	t1 = flatten_type(t1);
	t2 = flatten_type(t2);
	if ( t1 == t2 )
		return 1;

	if ( t1->Tag() != t2->Tag() )
		{
		if ( is_init )
			return is_init_compat(t1, t2) || is_init_compat(t2, t1);

		return 0;
		}

	switch ( t1->Tag() ) {
	case TYPE_VOID:
	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_STRING:
	case TYPE_PATTERN:
	case TYPE_TIMER:
	case TYPE_PORT:
	case TYPE_ADDR:
	case TYPE_SUBNET:
	case TYPE_ANY:
	case TYPE_ERROR:
		return 1;

	case TYPE_ENUM:
		// We should probably check to see whether all of the
		// enumerations are present and in the same location.
		// FIXME: Yes, but perhaps we should better return
		// true per default?
		return 1;

	case TYPE_TABLE:
		{
		const IndexType* it1 = (const IndexType*) t1;
		const IndexType* it2 = (const IndexType*) t2;

		TypeList* tl1 = it1->Indices();
		TypeList* tl2 = it2->Indices();

		if ( tl1 || tl2 )
			{
			if ( ! tl1 || ! tl2 || ! same_type(tl1, tl2, is_init, match_record_field_names) )
				return 0;
			}

		const BroType* y1 = t1->YieldType();
		const BroType* y2 = t2->YieldType();

		if ( y1 || y2 )
			{
			if ( ! y1 || ! y2 || ! same_type(y1, y2, is_init, match_record_field_names) )
				return 0;
			}

		return 1;
		}

	case TYPE_FUNC:
		{
		const FuncType* ft1 = (const FuncType*) t1;
		const FuncType* ft2 = (const FuncType*) t2;

		if ( ft1->Flavor() != ft2->Flavor() )
			return 0;

		if ( t1->YieldType() || t2->YieldType() )
			{
			if ( ! t1->YieldType() || ! t2->YieldType() ||
			     ! same_type(t1->YieldType(), t2->YieldType(), is_init, match_record_field_names) )
				return 0;
			}

		return ft1->CheckArgs(ft2->ArgTypes()->Types(), is_init);
		}

	case TYPE_RECORD:
		{
		const RecordType* rt1 = (const RecordType*) t1;
		const RecordType* rt2 = (const RecordType*) t2;

		if ( rt1->NumFields() != rt2->NumFields() )
			return 0;

		for ( int i = 0; i < rt1->NumFields(); ++i )
			{
			const TypeDecl* td1 = rt1->FieldDecl(i);
			const TypeDecl* td2 = rt2->FieldDecl(i);

			if ( (match_record_field_names && ! streq(td1->id, td2->id)) ||
			     ! same_type(td1->type, td2->type, is_init, match_record_field_names) )
				return 0;
			}

		return 1;
		}

	case TYPE_LIST:
		{
		const type_list* tl1 = t1->AsTypeList()->Types();
		const type_list* tl2 = t2->AsTypeList()->Types();

		if ( tl1->length() != tl2->length() )
			return 0;

		loop_over_list(*tl1, i)
			if ( ! same_type((*tl1)[i], (*tl2)[i], is_init, match_record_field_names) )
				return 0;

		return 1;
		}

	case TYPE_VECTOR:
	case TYPE_FILE:
		return same_type(t1->YieldType(), t2->YieldType(), is_init, match_record_field_names);

	case TYPE_OPAQUE:
		{
		const OpaqueType* ot1 = (const OpaqueType*) t1;
		const OpaqueType* ot2 = (const OpaqueType*) t2;
		return ot1->Name() == ot2->Name() ? 1 : 0;
		}

	case TYPE_TYPE:
		return same_type(t1, t2, is_init, match_record_field_names);

	case TYPE_UNION:
		reporter->Error("union type in same_type()");
	}
	return 0;
	}

int same_attrs(const Attributes* a1, const Attributes* a2)
	{
	if ( ! a1 )
		return (a2 == 0);

	if ( ! a2 )
		return (a1 == 0);

	return (*a1 == *a2);
	}

int record_promotion_compatible(const RecordType* super_rec,
				const RecordType* sub_rec)
	{
	for ( int i = 0; i < sub_rec->NumFields(); ++i )
		{
		int o = super_rec->FieldOffset(sub_rec->FieldName(i));

		if ( o < 0 )
			// Orphaned field.
			continue;

		BroType* sub_field_type = sub_rec->FieldType(i);
		BroType* super_field_type = super_rec->FieldType(o);

		if ( same_type(sub_field_type, super_field_type) )
			continue;

		if ( sub_field_type->Tag() != TYPE_RECORD )
			return 0;

		if ( super_field_type->Tag() != TYPE_RECORD )
			return 0;

		if ( ! record_promotion_compatible(super_field_type->AsRecordType(),
		                                   sub_field_type->AsRecordType()) )
			return 0;
		}

	return 1;
	}

const BroType* flatten_type(const BroType* t)
	{
	if ( t->Tag() != TYPE_LIST )
		return t;

	const TypeList* tl = t->AsTypeList();

	if ( tl->IsPure() )
		return tl->PureType();

	const type_list* types = tl->Types();

	if ( types->length() == 0 )
		reporter->InternalError("empty type list in flatten_type");

	const BroType* ft = (*types)[0];
	if ( types->length() == 1 || tl->AllMatch(ft, 0) )
		return ft;

	return t;
	}

BroType* flatten_type(BroType* t)
	{
	return (BroType*) flatten_type((const BroType*) t);
	}

int is_assignable(BroType* t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_STRING:
	case TYPE_PATTERN:
	case TYPE_ENUM:
	case TYPE_TIMER:
	case TYPE_PORT:
	case TYPE_ADDR:
	case TYPE_SUBNET:
	case TYPE_RECORD:
	case TYPE_FUNC:
	case TYPE_ANY:
	case TYPE_ERROR:
	case TYPE_LIST:
		return 1;

	case TYPE_VECTOR:
	case TYPE_FILE:
	case TYPE_OPAQUE:
	case TYPE_TABLE:
	case TYPE_TYPE:
		return 1;

	case TYPE_VOID:
		return 0;

	case TYPE_UNION:
		reporter->Error("union type in is_assignable()");
	}

	return 0;
	}

#define CHECK_TYPE(t) \
	if ( t1 == t || t2 == t ) \
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

		// Note - mixing two TYPE_COUNTER's still promotes to
		// a TYPE_COUNT.
		return TYPE_COUNT;
		}
	else
		{
		reporter->InternalError("non-arithmetic tags in max_type()");
		return TYPE_ERROR;
		}
	}

BroType* merge_types(const BroType* t1, const BroType* t2)
	{
	t1 = flatten_type(t1);
	t2 = flatten_type(t2);

	TypeTag tg1 = t1->Tag();
	TypeTag tg2 = t2->Tag();

	if ( BothArithmetic(tg1, tg2) )
		return base_type(max_type(tg1, tg2));

	if ( tg1 != tg2 )
		{
		t1->Error("incompatible types", t2);
		return 0;
		}

	switch ( tg1 ) {
	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_STRING:
	case TYPE_PATTERN:
	case TYPE_TIMER:
	case TYPE_PORT:
	case TYPE_ADDR:
	case TYPE_SUBNET:
	case TYPE_BOOL:
	case TYPE_ANY:
	case TYPE_ERROR:
		return base_type(tg1);

	case TYPE_ENUM:
		{
		// Could compare pointers t1 == t2, but maybe there's someone out
		// there creating clones of the type, so safer to compare name.
		if ( t1->GetName() != t2->GetName() )
			{
			std::string msg = fmt("incompatible enum types: '%s' and '%s'",
			                      t1->GetName().data(), t2->GetName().data());

			t1->Error(msg.data(), t2);
			return 0;
			}

		// Doing a lookup here as a roundabout way of ref-ing t1, without
		// changing the function params which has t1 as const and also
		// (potentially) avoiding a pitfall mentioned earlier about clones.
		auto id = global_scope()->Lookup(t1->GetName());

		if ( id && id->AsType() && id->AsType()->Tag() == TYPE_ENUM )
			// It should make most sense to return the real type here rather
			// than a copy since it may be redef'd later in parsing.  If we
			// return a copy, then whoever is using this return value won't
			// actually see those changes from the redef.
			return id->AsType()->Ref();

		std::string msg = fmt("incompatible enum types: '%s' and '%s'"
		                      " ('%s' enum type ID is invalid)",
		                      t1->GetName().data(), t2->GetName().data(),
		                      t1->GetName().data());
		t1->Error(msg.data(), t2);
		return 0;
		}

	case TYPE_TABLE:
		{
		const IndexType* it1 = (const IndexType*) t1;
		const IndexType* it2 = (const IndexType*) t2;

		const type_list* tl1 = it1->IndexTypes();
		const type_list* tl2 = it2->IndexTypes();
		TypeList* tl3 = 0;

		if ( tl1 || tl2 )
			{
			if ( ! tl1 || ! tl2 || tl1->length() != tl2->length() )
				{
				t1->Error("incompatible types", t2);
				return 0;
				}

			tl3 = new TypeList();

			loop_over_list(*tl1, i)
				{
				BroType* tl3_i = merge_types((*tl1)[i], (*tl2)[i]);
				if ( ! tl3_i )
					{
					Unref(tl3);
					return 0;
					}

				tl3->Append(tl3_i);
				}
			}

		const BroType* y1 = t1->YieldType();
		const BroType* y2 = t2->YieldType();
		BroType* y3 = 0;

		if ( y1 || y2 )
			{
			if ( ! y1 || ! y2 )
				{
				t1->Error("incompatible types", t2);
				Unref(tl3);
				return 0;
				}

			y3 = merge_types(y1, y2);
			if ( ! y3 )
				{
				Unref(tl3);
				return 0;
				}
			}

		if ( t1->IsSet() )
			return new SetType(tl3, 0);
		else
			return new TableType(tl3, y3);
		}

	case TYPE_FUNC:
		{
		if ( ! same_type(t1, t2) )
			{
			t1->Error("incompatible types", t2);
			return 0;
			}

		const FuncType* ft1 = (const FuncType*) t1;
		const FuncType* ft2 = (const FuncType*) t1;
		BroType* args = merge_types(ft1->Args(), ft2->Args());
		BroType* yield = t1->YieldType() ?
			merge_types(t1->YieldType(), t2->YieldType()) : 0;

		return new FuncType(args->AsRecordType(), yield, ft1->Flavor());
		}

	case TYPE_RECORD:
		{
		const RecordType* rt1 = (const RecordType*) t1;
		const RecordType* rt2 = (const RecordType*) t2;

		if ( rt1->NumFields() != rt2->NumFields() )
			return 0;

		type_decl_list* tdl3 = new type_decl_list(rt1->NumFields());

		for ( int i = 0; i < rt1->NumFields(); ++i )
			{
			const TypeDecl* td1 = rt1->FieldDecl(i);
			const TypeDecl* td2 = rt2->FieldDecl(i);
			BroType* tdl3_i = merge_types(td1->type, td2->type);

			if ( ! streq(td1->id, td2->id) || ! tdl3_i )
				{
				t1->Error("incompatible record fields", t2);
				delete tdl3;
				Unref(tdl3_i);
				return 0;
				}

			tdl3->push_back(new TypeDecl(tdl3_i, copy_string(td1->id)));
			}

		return new RecordType(tdl3);
		}

	case TYPE_LIST:
		{
		const TypeList* tl1 = t1->AsTypeList();
		const TypeList* tl2 = t2->AsTypeList();

		if ( tl1->IsPure() != tl2->IsPure() )
			{
			tl1->Error("incompatible lists", tl2);
			return 0;
			}

		const type_list* l1 = tl1->Types();
		const type_list* l2 = tl2->Types();

		if ( l1->length() == 0 || l2->length() == 0 )
			{
			if ( l1->length() == 0 )
				tl1->Error("empty list");
			else
				tl2->Error("empty list");
			return 0;
			}

		if ( tl1->IsPure() )
			{
			// We will be expanding the pure list when converting
			// the initialization expression into a set of values.
			// So the merge type of the list is the type of one
			// of the elements, providing they're consistent.
			return merge_types((*l1)[0], (*l2)[0]);
			}

		// Impure lists - must have the same size and match element
		// by element.
		if ( l1->length() != l2->length() )
			{
			tl1->Error("different number of indices", tl2);
			return 0;
			}

		TypeList* tl3 = new TypeList();
		loop_over_list(*l1, i)
			tl3->Append(merge_types((*l1)[i], (*l2)[i]));

		return tl3;
		}

	case TYPE_VECTOR:
		if ( ! same_type(t1->YieldType(), t2->YieldType()) )
			{
			t1->Error("incompatible types", t2);
			return 0;
			}

		return new VectorType(merge_types(t1->YieldType(), t2->YieldType()));

	case TYPE_FILE:
		if ( ! same_type(t1->YieldType(), t2->YieldType()) )
			{
			t1->Error("incompatible types", t2);
			return 0;
			}

		return new FileType(merge_types(t1->YieldType(), t2->YieldType()));

	case TYPE_UNION:
		reporter->InternalError("union type in merge_types()");
		return 0;

	default:
		reporter->InternalError("bad type in merge_types()");
		return 0;
	}
	}

BroType* merge_type_list(ListExpr* elements)
	{
	TypeList* tl_type = elements->Type()->AsTypeList();
	type_list* tl = tl_type->Types();

	if ( tl->length() < 1 )
		{
		reporter->Error("no type can be inferred for empty list");
		return 0;
		}

	BroType* t = (*tl)[0]->Ref();

	if ( tl->length() == 1 )
		return t;

	for ( int i = 1; t && i < tl->length(); ++i )
		{
		BroType* t_new = merge_types(t, (*tl)[i]);
		Unref(t);
		t = t_new;
		}

	if ( ! t )
		reporter->Error("inconsistent types in list");

	return t;
	}

// Reduces an aggregate type.
static BroType* reduce_type(BroType* t)
	{
	if ( t->Tag() == TYPE_LIST )
		return flatten_type(t);

	else if ( t->IsSet() )
		{
		TypeList* tl = t->AsTableType()->Indices();
		if ( tl->Types()->length() == 1 )
			return (*tl->Types())[0];
		else
			return tl;
		}

	else
		return t;
	}

BroType* init_type(Expr* init)
	{
	if ( init->Tag() != EXPR_LIST )
		{
		BroType* t = init->InitType();
		if ( ! t )
			return 0;

		if ( t->Tag() == TYPE_LIST &&
		     t->AsTypeList()->Types()->length() != 1 )
			{
			init->Error("list used in scalar initialization");
			Unref(t);
			return 0;
			}

		return t;
		}

	ListExpr* init_list = init->AsListExpr();
	const expr_list& el = init_list->Exprs();

	if ( el.length() == 0 )
		{
		init->Error("empty list in untyped initialization");
		return 0;
		}

	// Could be a record, a set, or a list of table elements.
	Expr* e0 = el[0];
	if ( e0->IsRecordElement(0) )
		// ListExpr's know how to build a record from their
		// components.
		return init_list->InitType();

	BroType* t = e0->InitType();
	if ( t )
		t = reduce_type(t);
	if ( ! t )
		return 0;

	for ( int i = 1; t && i < el.length(); ++i )
		{
		BroType* el_t = el[i]->InitType();
		BroType* ti = el_t ? reduce_type(el_t) : 0;
		if ( ! ti )
			{
			Unref(t);
			return 0;
			}

		if ( same_type(t, ti) )
			{
			Unref(ti);
			continue;
			}

		BroType* t_merge = merge_types(t, ti);
		Unref(t);
		Unref(ti);
		t = t_merge;
		}

	if ( ! t )
		{
		init->Error("type error in initialization");
		return 0;
		}

	if ( t->Tag() == TYPE_TABLE && ! t->AsTableType()->IsSet() )
		// A list of table elements.
		return t;

	// A set.  If the index type isn't yet a type list, make
	// it one, as that's what's required for creating a set type.
	if ( t->Tag() != TYPE_LIST )
		{
		TypeList* tl = new TypeList(t);
		tl->Append(t);
		t = tl;
		}

	return new SetType(t->AsTypeList(), 0);
	}

bool is_atomic_type(const BroType* t)
	{
	switch ( t->InternalType() ) {
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
