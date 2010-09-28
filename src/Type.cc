// $Id: Type.cc 6916 2009-09-24 20:48:36Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "Type.h"
#include "Attr.h"
#include "Expr.h"
#include "Scope.h"
#include "Serializer.h"

RecordType* init_global_attrs();

bool in_global_attr_decl = false;
RecordType* global_attributes_type = init_global_attrs();

RecordType* init_global_attrs()
	{
	in_global_attr_decl = true;
	RecordType* rt = new RecordType(new type_decl_list);
	in_global_attr_decl = false;
	rt->MakeGlobalAttributeType();
	return rt;
	}

const char* type_name(TypeTag t)
	{
	static char errbuf[512];

	static const char* type_names[int(NUM_TYPES)] = {
		"void",
		"bool", "int", "count", "counter",
		"double", "time", "interval",
		"string", "pattern",
		"enum",
		"timer",
		"port", "addr", "net", "subnet",
		"any",
		"table", "union", "record", "types",
		"func",
		"file",
		"vector",
		"error",
	};

	if ( int(t) >= NUM_TYPES )
		{
		snprintf(errbuf, sizeof(errbuf), "%d: not a type tag", int(t));
		return errbuf;
		}

	return type_names[int(t)];
	}

BroType::BroType(TypeTag t, bool arg_base_type)
	{
	tag = t;
	is_network_order = 0;
	base_type = arg_base_type;
	is_global_attributes_type = false;

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
	case TYPE_NET:
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
	case TYPE_VECTOR:
		internal_tag = TYPE_INTERNAL_OTHER;
		break;

	case TYPE_ERROR:
		internal_tag = TYPE_INTERNAL_ERROR;
		break;
	}

	// Kind of hacky; we don't want an error while we're defining
	// the global attrs!
	if ( in_global_attr_decl )
		{
		attributes_type = 0;
		return;
		}

	if ( ! global_attributes_type )
		SetError();
	else
		attributes_type = global_attributes_type;
	}

bool BroType::SetAttributesType(type_decl_list* attr_types)
	{
	TypeList* global = new TypeList();
	global->Append(global_attributes_type);

	attributes_type = refine_type(global, attr_types)->AsRecordType();

	return (attributes_type != 0);
	}

int BroType::MatchesIndex(ListExpr*& /* index */) const
	{
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

void BroType::SetError()
	{
	tag = TYPE_ERROR;
	}

unsigned int BroType::MemoryAllocation() const
	{
	return padded_sizeof(*this);
	}

bool BroType::Serialize(SerialInfo* info) const
	{
	// We always send full types (see below).
	SERIALIZE(true);

	bool ret = SerialObj::Serialize(info);
	return ret;
	}

BroType* BroType::Unserialize(UnserialInfo* info, TypeTag want)
	{
	// To avoid external Broccoli clients needing to always send full type
	// objects, we allow them to give us only the name of a type. To
	// differentiate between the two cases, we exchange a flag first.
	bool full_type = true;;
	if ( ! UNSERIALIZE(&full_type) )
		return 0;

	if ( ! full_type )
		{
		const char* name;
		if ( ! UNSERIALIZE_STR(&name, 0) )
			return 0;

		ID* id = global_scope()->Lookup(name);
		if ( ! id )
			{
			info->s->Error(fmt("unknown type %s", name));
			return 0;
			}

		BroType* t = id->AsType();
		if ( ! t )
			{
			info->s->Error(fmt("%s is not a type", name));
			return 0;
			}

		return t->Ref();
		}

	BroType* t = (BroType*) SerialObj::Unserialize(info, SER_BRO_TYPE);

	if ( ! t )
		return 0;

	// For base types, we return our current instance.
	if ( t->base_type )
		{
		BroType* t2 = ::base_type(TypeTag(t->tag));
		Unref(t);
		assert(t2);
		return t2;
		}

	// For the global_attribute_type, we also return our current instance.
	if ( t->is_global_attributes_type )
		{
		BroType* t2 = global_attributes_type;
		Unref(t);
		t2->Ref();
		assert(t2);
		return t2;
		}

	assert(t);
	return t;
	}

IMPLEMENT_SERIAL(BroType, SER_BRO_TYPE)

bool BroType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BRO_TYPE, BroObj);

	info->s->WriteOpenTag("Type");

	if ( ! (SERIALIZE(char(tag)) && SERIALIZE(char(internal_tag))) )
		return false;

	if ( ! (SERIALIZE(is_network_order) && SERIALIZE(base_type) &&
		SERIALIZE(is_global_attributes_type)) )
		return false;

	SERIALIZE_OPTIONAL(attributes_type);

	info->s->WriteCloseTag("Type");

	return true;
	}

bool BroType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	char c1, c2;
	if ( ! (UNSERIALIZE(&c1) && UNSERIALIZE(&c2) ) )
		return 0;

	tag = (TypeTag) c1;
	internal_tag = (InternalTypeTag) c2;

	if ( ! (UNSERIALIZE(&is_network_order) && UNSERIALIZE(&base_type)
			&& UNSERIALIZE(&is_global_attributes_type)) )
		return 0;

	BroType* type;
	UNSERIALIZE_OPTIONAL(type, BroType::Unserialize(info, TYPE_RECORD));
	attributes_type = (RecordType*) type;

	return true;
	}

TypeList::~TypeList()
	{
	loop_over_list(types, i)
		Unref(types[i]);

	Unref(pure_type);
	}

int TypeList::AllMatch(const BroType* t, int is_init) const
	{
	loop_over_list(types, i)
		if ( ! same_type(types[i], t, is_init) )
			return 0;
	return 1;
	}

void TypeList::Append(BroType* t)
	{
	if ( pure_type && ! same_type(t, pure_type) )
		internal_error("pure type-list violation");

	types.append(t);
	}

void TypeList::AppendEvenIfNotPure(BroType* t)
	{
	if ( pure_type && ! same_type(t, pure_type) )
		{
		Unref(pure_type);
		pure_type = 0;
		}

	types.append(t);
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

IMPLEMENT_SERIAL(TypeList, SER_TYPE_LIST);

bool TypeList::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_TYPE_LIST, BroType);

	SERIALIZE_OPTIONAL(pure_type);

	if ( ! SERIALIZE(types.length()) )
		return false;

	loop_over_list(types, j)
		{
		if ( ! types[j]->Serialize(info) )
			return false;
		}

	return true;
	}

bool TypeList::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroType);

	UNSERIALIZE_OPTIONAL(pure_type, BroType::Unserialize(info));

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	while ( len-- )
		{
		BroType* t = BroType::Unserialize(info);
		if ( ! t )
			return false;

		types.append(t);
		}
	return true;
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

bool IndexType::IsSubNetIndex() const
	{
	const type_list* types = indices->Types();
	if ( types->length() == 1 && (*types)[0]->Tag() == TYPE_SUBNET )
		return true;
	return false;
	}

IMPLEMENT_SERIAL(IndexType, SER_INDEX_TYPE);

bool IndexType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_INDEX_TYPE, BroType);

	SERIALIZE_OPTIONAL(yield_type);
	return indices->Serialize(info);
	}

bool IndexType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroType);

	UNSERIALIZE_OPTIONAL(yield_type, BroType::Unserialize(info));
	indices = (TypeList*) BroType::Unserialize(info, TYPE_LIST);
	return indices != 0;
	}

TableType::TableType(TypeList* ind, BroType* yield)
: IndexType(TYPE_TABLE, ind, yield)
	{
	if ( ! indices )
		return;

	type_list* tl = indices->Types();

	loop_over_list(*tl, i)
		{
		BroType* tli = (*tl)[i];
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

IMPLEMENT_SERIAL(TableType, SER_TABLE_TYPE);

bool TableType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_TABLE_TYPE, IndexType);
	return true;
	}

bool TableType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(IndexType);
	return true;
	}

SetType::~SetType()
	{
	Unref(elements);
	}

IMPLEMENT_SERIAL(SetType, SER_SET_TYPE);

bool SetType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SET_TYPE, TableType);

	SERIALIZE_OPTIONAL(elements);
	return true;
	}

bool SetType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(TableType);

	UNSERIALIZE_OPTIONAL(elements, (ListExpr*) Expr::Unserialize(info, EXPR_LIST));
	return true;
	}

FuncType::FuncType(RecordType* arg_args, BroType* arg_yield, int arg_is_event)
: BroType(TYPE_FUNC)
	{
	args = arg_args;
	yield = arg_yield;
	is_event = arg_is_event;

	arg_types = new TypeList();

	for ( int i = 0; i < args->NumFields(); ++i )
		arg_types->Append(args->FieldType(i)->Ref());
	}

FuncType::~FuncType()
	{
	Unref(arg_types);
	}

BroType* FuncType::YieldType()
	{
	return yield;
	}

int FuncType::MatchesIndex(ListExpr*& index) const
	{
	return check_and_promote_exprs(index, arg_types) ?
			MATCHES_INDEX_SCALAR : DOES_NOT_MATCH_INDEX;
	}

int FuncType::CheckArgs(const type_list* args) const
	{
	const type_list* my_args = arg_types->Types();

	if ( my_args->length() != args->length() )
		return 0;

	for ( int i = 0; i < my_args->length(); ++i )
		if ( ! same_type((*args)[i], (*my_args)[i]) )
			return 0;

	return 1;
	}

void FuncType::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		{
		d->Add(is_event ? "event" : "function");
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
		d->Add(is_event);
		d->Add(yield != 0);
		args->DescribeFields(d);
		if ( yield )
			yield->Describe(d);
		}
	}

IMPLEMENT_SERIAL(FuncType, SER_FUNC_TYPE);

bool FuncType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FUNC_TYPE, BroType);

	assert(args);
	assert(arg_types);

	SERIALIZE_OPTIONAL(yield);

	return args->Serialize(info) &&
		arg_types->Serialize(info) &&
		SERIALIZE(is_event);
	}

bool FuncType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroType);

	UNSERIALIZE_OPTIONAL(yield, BroType::Unserialize(info));

	args = (RecordType*) BroType::Unserialize(info, TYPE_RECORD);
	if ( ! args )
		return false;

	arg_types = (TypeList*) BroType::Unserialize(info, TYPE_LIST);
	if ( ! arg_types )
		return false;

	return UNSERIALIZE(&is_event);
	}

TypeDecl::TypeDecl(BroType* t, const char* i, attr_list* arg_attrs)
	{
	type = t;
	attrs = arg_attrs ? new Attributes(arg_attrs, t) : 0;
	id = i;

	if ( in_global_attr_decl && ! attrs->FindAttr(ATTR_DEFAULT) )
		error("global attribute types must have default values");
	}

TypeDecl::~TypeDecl()
	{
	Unref(type);
	Unref(attrs);
	delete [] id;
	}

bool TypeDecl::Serialize(SerialInfo* info) const
	{
	assert(type);
	assert(id);

	SERIALIZE_OPTIONAL(attrs);

	return type->Serialize(info) && SERIALIZE(id);
	}

TypeDecl* TypeDecl::Unserialize(UnserialInfo* info)
	{
	TypeDecl* t = new TypeDecl(0, 0, 0);

	UNSERIALIZE_OPTIONAL_STATIC(t->attrs, Attributes::Unserialize(info), t);
	t->type = BroType::Unserialize(info);

	if ( ! (t->type && UNSERIALIZE_STR(&t->id, 0)) )
		{
		delete t;
		return 0;
		}

	return t;
	}

RecordField::RecordField(int arg_base, int arg_offset, int arg_total_offset)
	{
	base = arg_base;
	offset = arg_offset;
	total_offset = arg_total_offset;
	}

RecordType::RecordType(type_decl_list* arg_types) : BroType(TYPE_RECORD)
	{
	types = arg_types;
	base = 0;
	fields = 0;
	num_fields = types ? types->length() : 0;
	}

RecordType::RecordType(TypeList* arg_base, type_decl_list* refinements)
: BroType(TYPE_RECORD)
	{
	if ( refinements )
		arg_base->Append(new RecordType(refinements));

	Init(arg_base);
	}

void RecordType::Init(TypeList* arg_base)
	{
	base = arg_base;

	if ( ! base )
		Internal("empty RecordType");

	fields = new PDict(RecordField)(ORDERED);
	types = 0;

	type_list* t = base->Types();
	loop_over_list(*t, i)
		{
		BroType* ti = (*t)[i];
		if ( ti->Tag() != TYPE_RECORD )
			(*t)[i]->Error("non-record in base type list");

		RecordType* rti = ti->AsRecordType();
		int n = rti->NumFields();

		for ( int j = 0; j < n; ++j )
			{
			const TypeDecl* tdij = rti->FieldDecl(j);
			if ( fields->Lookup(tdij->id) )
				{
				error("duplicate field", tdij->id);
				continue;
				}

			RecordField* rf = new RecordField(i, j, fields->Length());
			if ( fields->Insert(tdij->id, rf) )
				Internal("duplicate field when constructing record");
			}
		}

	num_fields = fields->Length();
	}

RecordType::~RecordType()
	{
	if ( types )
		{
		loop_over_list(*types, i)
			delete (*types)[i];
		delete types;
		}

	delete fields;
	Unref(base);
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
	if ( types )
		return (*types)[field]->type;
	else
		{
		RecordField* rf = fields->NthEntry(field);
		if ( ! rf )
			Internal("missing field in RecordType::FieldType");
		BroType* bt = (*base->Types())[rf->base];
		RecordType* rbt = bt->AsRecordType();
		return rbt->FieldType(rf->offset);
		}
	}

int RecordType::FieldOffset(const char* field) const
	{
	if ( types )
		{
		loop_over_list(*types, i)
			{
			TypeDecl* td = (*types)[i];
			if ( streq(td->id, field) )
				return i;
			}

		return -1;
		}

	else
		{
		RecordField* rf = fields->Lookup(field);
		if ( ! rf )
			return -1;
		else
			return rf->total_offset;
		}
	}

const char* RecordType::FieldName(int field) const
	{
	return FieldDecl(field)->id;
	}

const TypeDecl* RecordType::FieldDecl(int field) const
	{
	if ( types )
		return (*types)[field];
	else
		{
		RecordField* rf = fields->NthEntry(field);
		if ( ! rf )
			internal_error("missing field in RecordType::FieldDecl");

		BroType* bt = (*base->Types())[rf->base];
		RecordType* rbt = bt->AsRecordType();
		return rbt->FieldDecl(rf->offset);
		}
	}

TypeDecl* RecordType::FieldDecl(int field)
	{
	if ( types )
		return (*types)[field];
	else
		{
		RecordField* rf = fields->NthEntry(field);
		if ( ! rf )
			Internal("missing field in RecordType::FieldDecl");
		BroType* bt = (*base->Types())[rf->base];
		RecordType* rbt = bt->AsRecordType();
		return rbt->FieldDecl(rf->offset);
		}
	}

void RecordType::Describe(ODesc* d) const
	{
	if ( d->IsReadable() )
		{
		d->AddSP("record {");
		DescribeFields(d);
		d->SP();
		d->Add("}");
		}

	else
		{
		d->Add(int(Tag()));
		DescribeFields(d);
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
			loop_over_list(*types, i)
				{
				(*types)[i]->type->Describe(d);
				d->SP();
				d->Add((*types)[i]->id);
				d->SP();
				}
			}
		else
			{
			d->AddCount(1);
			base->Describe(d);
			}
		}
	}

IMPLEMENT_SERIAL(RecordType, SER_RECORD_TYPE)

bool RecordType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_RECORD_TYPE, BroType);

	if ( ! SERIALIZE(num_fields) )
		return false;

	if ( types )
		{
		if ( ! (SERIALIZE(true) && SERIALIZE(types->length())) )
			return false;

		loop_over_list(*types, i)
			{
			if ( ! (*types)[i]->Serialize(info) )
				return false;
			}
		}

	else if ( ! SERIALIZE(false) )
		return false;

	SERIALIZE_OPTIONAL(base);

	// We don't serialize the fields as we can reconstruct them.
	return true;
	}

bool RecordType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroType);

	if ( ! UNSERIALIZE(&num_fields) )
		return false;

	bool has_it;
	if ( ! UNSERIALIZE(&has_it) )
		return false;

	if ( has_it )
		{
		int len;
		if ( ! UNSERIALIZE(&len) )
			return false;

		types = new type_decl_list(len);

		while ( len-- )
			{
			TypeDecl* t = TypeDecl::Unserialize(info);
			if ( ! t )
				return false;

			types->append(t);
			}
		}
	else
		types = 0;

	BroType* type;
	UNSERIALIZE_OPTIONAL(type, BroType::Unserialize(info, TYPE_LIST));
	base = (TypeList*) type;

	if ( base )
		Init(base);

	return true;
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

IMPLEMENT_SERIAL(SubNetType, SER_SUBNET_TYPE);

bool SubNetType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SUBNET_TYPE, BroType);
	return true;
	}

bool SubNetType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroType);
	return true;
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

IMPLEMENT_SERIAL(FileType, SER_FILE_TYPE);

bool FileType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_FILE_TYPE, BroType);

	assert(yield);
	return yield->Serialize(info);
	}

bool FileType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroType);

	yield = BroType::Unserialize(info);
	return yield != 0;
	}

EnumType::EnumType(bool arg_is_export)
: BroType(TYPE_ENUM)
	{
	is_export = arg_is_export;
	counter = 0;
	}

EnumType::~EnumType()
	{
	for ( NameMap::iterator iter = names.begin(); iter != names.end(); ++iter )
		delete [] iter->first;
	}

int EnumType::AddName(const string& module_name, const char* name)
	{
	ID* id = lookup_ID(name, module_name.c_str());
	if ( ! id )
		{
		id = install_ID(name, module_name.c_str(), true, is_export);
		id->SetType(this->Ref());
		id->SetEnumConst();
		}
	else
		{
		debug_msg("identifier already exists: %s\n", name);
		return -1;
		}

	string fullname = make_full_var_name(module_name.c_str(), name);
	names[copy_string(fullname.c_str())] = counter;
	return counter++;
	}

int EnumType::AddNamesFrom(const string& module_name, EnumType* et)
	{
	int last_added = counter;
	for ( NameMap::iterator iter = et->names.begin();
	      iter != et->names.end(); ++iter )
		{
		ID* id = lookup_ID(iter->first, module_name.c_str());
		id->SetType(this->Ref());
		names[copy_string(id->Name())] = counter;
		last_added = counter++;
		}

	return last_added;
	}

int EnumType::Lookup(const string& module_name, const char* name)
	{
	NameMap::iterator pos =
		names.find(make_full_var_name(module_name.c_str(), name).c_str());

	if ( pos == names.end() )
		return -1;
	else
		return pos->second;
	}

const char* EnumType::Lookup(int value)
	{
	for ( NameMap::iterator iter = names.begin();
	      iter != names.end(); ++iter )
		if ( iter->second == value )
			return iter->first;

	return 0;
	}

IMPLEMENT_SERIAL(EnumType, SER_ENUM_TYPE);

bool EnumType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ENUM_TYPE, BroType);

	// I guess we don't really need both ...
	if ( ! (SERIALIZE(counter) && SERIALIZE((unsigned int) names.size()) &&
		SERIALIZE(is_export)) )
		return false;

	for ( NameMap::const_iterator iter = names.begin();
	      iter != names.end(); ++iter )
		{
		if ( ! SERIALIZE(iter->first) || ! SERIALIZE(iter->second) )
			return false;
		}

	return true;
	}

bool EnumType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroType);

	unsigned int len;
	if ( ! UNSERIALIZE(&counter) ||
	     ! UNSERIALIZE(&len) ||
	     ! UNSERIALIZE(&is_export) )
		return false;

	while ( len-- )
		{
		const char* name;
		int val;
		if ( ! (UNSERIALIZE_STR(&name, 0) && UNSERIALIZE(&val)) )
			return false;

		names[name] = val;
		}

	return true;
	}

VectorType::VectorType(BroType* element_type)
: BroType(TYPE_VECTOR)
	{
	if ( element_type )
		yield_type = element_type;
	}

VectorType::~VectorType()
	{
	Unref(yield_type);
	}

int VectorType::MatchesIndex(ListExpr*& index) const
	{
	expr_list& el = index->Exprs();

	if ( el.length() != 1 )
		return DOES_NOT_MATCH_INDEX;

	if ( el[0]->Type()->Tag() == TYPE_VECTOR )
		return (IsIntegral(el[0]->Type()->YieldType()->Tag()) ||
			 IsBool(el[0]->Type()->YieldType()->Tag())) ?
				MATCHES_INDEX_VECTOR : DOES_NOT_MATCH_INDEX;
	else
		return (IsIntegral(el[0]->Type()->Tag()) ||
			 IsBool(el[0]->Type()->Tag())) ?
				MATCHES_INDEX_SCALAR : DOES_NOT_MATCH_INDEX;
	}

IMPLEMENT_SERIAL(VectorType, SER_VECTOR_TYPE);

bool VectorType::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_VECTOR_TYPE, BroType);
	return yield_type->Serialize(info);
	}

bool VectorType::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroType);
	yield_type = BroType::Unserialize(info);
	return yield_type != 0;
	}

BroType* refine_type(TypeList* base, type_decl_list* refinements)
	{
	type_list* t = base->Types();

	if ( t->length() == 1 && ! refinements )
		{ // Just a direct reference to a single type.
		BroType* rt = (*t)[0]->Ref();
		Unref(base);
		return rt;
		}

	return new RecordType(base, refinements);
	}


BroType* base_type(TypeTag tag)
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

	return base_types[t]->Ref();
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

int same_type(const BroType* t1, const BroType* t2, int is_init)
	{
	if ( t1 == t2 )
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
	case TYPE_NET:
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
			if ( ! tl1 || ! tl2 || ! same_type(tl1, tl2, is_init) )
				return 0;
			}

		const BroType* y1 = t1->YieldType();
		const BroType* y2 = t2->YieldType();

		if ( y1 || y2 )
			{
			if ( ! y1 || ! y2 || ! same_type(y1, y2, is_init) )
				return 0;
			}

		return 1;
		}

	case TYPE_FUNC:
		{
		const FuncType* ft1 = (const FuncType*) t1;
		const FuncType* ft2 = (const FuncType*) t2;

		if ( ft1->IsEvent() != ft2->IsEvent() )
			return 0;

		if ( t1->YieldType() || t2->YieldType() )
			{
			if ( ! t1->YieldType() || ! t2->YieldType() ||
			     ! same_type(t1->YieldType(), t2->YieldType(), is_init) )
				return 0;
			}

		return same_type(ft1->Args(), ft2->Args(), is_init);
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

			if ( ! streq(td1->id, td2->id) ||
			     ! same_type(td1->type, td2->type, is_init) )
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
			if ( ! same_type((*tl1)[i], (*tl2)[i], is_init) )
				return 0;

		return 1;
		}

	case TYPE_VECTOR:
	case TYPE_FILE:
		return same_type(t1->YieldType(), t2->YieldType(), is_init);

	case TYPE_UNION:
		error("union type in same_type()");
	}
	return 0;
	}

int record_promotion_compatible(const RecordType* /* super_rec */,
				const RecordType* /* sub_rec */)
	{
#if 0
	int n = sub_rec->NumFields();

	for ( int i = 0; i < n; ++i )
		{
		if ( ! super_rec->HasField(sub_rec->FieldName(i)) )
			return 0;
		}
#endif

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
		internal_error("empty type list in flatten_type");

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
	case TYPE_NET:
	case TYPE_SUBNET:
	case TYPE_RECORD:
	case TYPE_FUNC:
	case TYPE_ANY:
	case TYPE_ERROR:
	case TYPE_LIST:
		return 1;

	case TYPE_VECTOR:
	case TYPE_FILE:
	case TYPE_TABLE:
		return 1;

	case TYPE_VOID:
		return 0;

	case TYPE_UNION:
		error("union type in is_assignable()");
	}

	return 0;
	}

TypeTag max_type(TypeTag t1, TypeTag t2)
	{
	if ( t1 == TYPE_INTERVAL || t1 == TYPE_TIME )
		t1 = TYPE_DOUBLE;
	if ( t2 == TYPE_INTERVAL || t2 == TYPE_TIME )
		t2 = TYPE_DOUBLE;

	if ( BothArithmetic(t1, t2) )
		{
#define CHECK_TYPE(t) \
	if ( t1 == t || t2 == t ) \
		return t;

		CHECK_TYPE(TYPE_DOUBLE);
		CHECK_TYPE(TYPE_INT);
		CHECK_TYPE(TYPE_COUNT);

		// Note - mixing two TYPE_COUNTER's still promotes to
		// a TYPE_COUNT.
		return TYPE_COUNT;
		}
	else
		{
		internal_error("non-arithmetic tags in max_type()");
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
	case TYPE_NET:
	case TYPE_SUBNET:
	case TYPE_ANY:
	case TYPE_ERROR:
		return base_type(tg1);

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
		else if ( tg1 == TYPE_TABLE )
			return new TableType(tl3, y3);
		else
			{
			internal_error("bad tag in merge_types");
			return 0;
			}
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

		return new FuncType(args->AsRecordType(), yield, ft1->IsEvent());
		}

	case TYPE_RECORD:
		{
		const RecordType* rt1 = (const RecordType*) t1;
		const RecordType* rt2 = (const RecordType*) t2;

		if ( rt1->NumFields() != rt2->NumFields() )
			return 0;

		type_decl_list* tdl3 = new type_decl_list;

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

			tdl3->append(new TypeDecl(tdl3_i, copy_string(td1->id)));
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
		internal_error("union type in merge_types()");
		return 0;

	default:
		internal_error("bad type in merge_types()");
		return 0;
	}
	}

BroType* merge_type_list(ListExpr* elements)
	{
	TypeList* tl_type = elements->Type()->AsTypeList();
	type_list* tl = tl_type->Types();

	if ( tl->length() < 1 )
		{
		error("no type can be inferred for empty list");
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
		error("inconsistent types in list");

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
