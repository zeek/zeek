// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/DefItem.h"

#include "zeek/Expr.h"

namespace zeek::detail
	{

DefinitionItem::DefinitionItem(const ID* _id) : name(_id->Name())
	{
	is_id = true;
	id = _id;
	di = nullptr;
	field_name = nullptr;

	t = id->GetType();

	CheckForRecord();
	}

DefinitionItem::DefinitionItem(const DefinitionItem* _di, const char* _field_name, TypePtr _t)
	{
	is_id = false;
	id = nullptr;
	di = _di;
	field_name = _field_name;

	t = std::move(_t);

	name += di->Name();
	name += '$';
	name += field_name;

	CheckForRecord();
	}

std::shared_ptr<DefinitionItem> DefinitionItem::FindField(const char* field) const
	{
	if ( ! IsRecord() )
		return nullptr;

	auto offset = rt->FieldOffset(field);

	return FindField(offset);
	}

std::shared_ptr<DefinitionItem> DefinitionItem::FindField(int offset) const
	{
	if ( ! IsRecord() )
		return nullptr;

	return (*fields)[offset];
	}

std::shared_ptr<DefinitionItem> DefinitionItem::CreateField(const char* field, TypePtr t)
	{
	auto offset = rt->FieldOffset(field);

	if ( (*fields)[offset] )
		return (*fields)[offset];

	(*fields)[offset] = std::make_shared<DefinitionItem>(this, field, std::move(t));

	return (*fields)[offset];
	}

std::shared_ptr<DefinitionItem> DefinitionItem::CreateField(int offset, TypePtr t)
	{
	if ( (*fields)[offset] )
		return (*fields)[offset];

	auto field = rt->FieldName(offset);

	(*fields)[offset] = std::make_shared<DefinitionItem>(this, field, std::move(t));

	return (*fields)[offset];
	}

void DefinitionItem::CheckForRecord()
	{
	if ( ! IsRecord() )
		{
		rt = nullptr;
		return;
		}

	rt = t->AsRecordType();
	num_fields = rt->NumFields();
	fields = std::vector<std::shared_ptr<DefinitionItem>>(num_fields);
	}

std::shared_ptr<DefinitionItem> DefItemMap::GetExprDI(const Expr* expr)
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

std::shared_ptr<DefinitionItem> DefItemMap::GetID_DI(const ID* id)
	{
	auto di = i2d.find(id);
	if ( di == i2d.end() )
		{
		auto new_entry = std::make_shared<DefinitionItem>(id);
		i2d[id] = new_entry;
		return new_entry;
		}
	else
		return di->second;
	}

const DefinitionItem* DefItemMap::GetConstID_DI(const ID* id) const
	{
	auto di = i2d.find(id);
	return di == i2d.end() ? nullptr : di->second.get();
	}

const DefinitionItem* DefItemMap::GetConstID_DI(const DefinitionItem* di,
                                                const char* field_name) const
	{
	return di->FindField(field_name).get();
	}

	} // zeek::detail
