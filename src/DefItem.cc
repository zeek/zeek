// See the file "COPYING" in the main distribution directory for copyright.

#include "DefItem.h"


DefinitionItem::DefinitionItem(const ID* _id)
	{
	is_id = true;
	id = _id;
	di = nullptr;
	field_name = nullptr;
	name = nullptr;

	t = id->Type();

	CheckForRecord();
	}

DefinitionItem::DefinitionItem(const DefinitionItem* _di,
				const char* _field_name, const BroType* _t)
	{
	is_id = false;
	id = nullptr;
	di = _di;
	field_name = _field_name;

	t = _t;

	auto di_n = di->Name();
	auto nl = strlen(di_n) + 1 /* $ */ + strlen(field_name) + 1;
	name = new char[nl];
	snprintf(name, nl, "%s$%s", di->Name(), field_name);

	CheckForRecord();
	}

DefinitionItem::~DefinitionItem()
	{
	if ( fields )
		{
		for ( int i = 0; i < num_fields; ++i )
			delete fields[i];

		delete fields;
		}

	delete name;
	}

DefinitionItem* DefinitionItem::FindField(const char* field) const
	{
	if ( ! IsRecord() )
		return nullptr;

	auto offset = rt->FieldOffset(field);

	return fields[offset];
	}

DefinitionItem* DefinitionItem::CreateField(const char* field, const BroType* t)
	{
	auto offset = rt->FieldOffset(field);

	fields[offset] = new DefinitionItem(this, field, t);

	return fields[offset];
	}

void DefinitionItem::CheckForRecord()
	{
	if ( ! IsRecord() )
		{
		rt = nullptr;
		fields = nullptr;
		return;
		}

	rt = t->AsRecordType();
	num_fields = rt->NumFields();
	fields = new DefinitionItem*[num_fields];

	for ( int i = 0; i < num_fields; ++i )
		fields[i] = nullptr;
	}
