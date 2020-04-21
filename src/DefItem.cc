// See the file "COPYING" in the main distribution directory for copyright.

#include "DefItem.h"
#include "Expr.h"


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

	return FindField(offset);
	}

DefinitionItem* DefinitionItem::FindField(int offset) const
	{
	if ( ! IsRecord() )
		return nullptr;

	return fields[offset];
	}

DefinitionItem* DefinitionItem::CreateField(const char* field, const BroType* t)
	{
	auto offset = rt->FieldOffset(field);

	if ( fields[offset] )
		return fields[offset];

	fields[offset] = new DefinitionItem(this, field, t);

	return fields[offset];
	}

DefinitionItem* DefinitionItem::CreateField(int offset, const BroType* t)
	{
	if ( fields[offset] )
		return fields[offset];

	auto field = rt->FieldName(offset);

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


DefinitionItem* DefItemMap::GetID_DI(const ID* id)
	{
	auto di = i2d.find(id);
	if ( di == i2d.end() )
		{
		auto new_entry = new DefinitionItem(id);
		i2d[id] = new_entry;
		return new_entry;
		}
	else
		return di->second;
	}

const DefinitionItem* DefItemMap::GetConstID_DI(const ID* id) const
	{
	auto di = i2d.find(id);
	if ( di != i2d.end() )
		return di->second;
	else
		return nullptr;
	}

const DefinitionItem* DefItemMap::GetConstID_DI(const DefinitionItem* di,
					const char* field_name) const
	{
	return di->FindField(field_name);
	}

DefinitionItem* DefItemMap::GetExprDI(const Expr* expr)
	{
	if ( expr->Tag() == EXPR_NAME )
		{
		auto id_e = expr->AsNameExpr();
		auto id = id_e->Id();
		return GetID_DI(id);
		}

	else if ( expr->Tag() == EXPR_FIELD )
		{
		auto f = expr->AsFieldExpr();
		auto r = f->Op();

		auto r_def = GetExprDI(r);

		if ( ! r_def )
			return nullptr;

		auto field = f->FieldName();
		return r_def->FindField(field);
		}

	else
		return nullptr;
	}

static DefinitionPoint no_def;

