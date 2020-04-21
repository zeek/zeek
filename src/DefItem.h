// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "DefPoint.h"
#include "ID.h"
#include "Type.h"


class DefinitionItem {
public:
	DefinitionItem(const ID* _id);
	DefinitionItem(const DefinitionItem* _di, const char* _field_name,
			const BroType* _t);

	~DefinitionItem();

	bool IsRecord() const	{ return t->Tag() == TYPE_RECORD; }

	const char* Name() const	{ return name ? name : id->Name(); }
	const BroType* Type() const	{ return t; }

	// For this definition item, look for a field corresponding
	// to the given name.
	DefinitionItem* FindField(const char* field) const;
	DefinitionItem* FindField(int offset) const;
	DefinitionItem* CreateField(const char* field, const BroType* t);
	DefinitionItem* CreateField(int offset, const BroType* t);

protected:
	void CheckForRecord();

	bool is_id;
	const ID* id;
	const DefinitionItem* di;
	const char* field_name;

	const BroType* t;

	char* name;

	const RecordType* rt;
	DefinitionItem** fields;	// indexed by field offset
	int num_fields;
};

typedef std::map<const ID*, DefinitionItem*> ID_to_DI_Map;

class DefItemMap {
public:
	~DefItemMap()
		{
		for ( auto& i2d : i2d )
			delete i2d.second;
		}

	// Gets definition for either a name or a record field reference.
	// Returns nil if "expr" lacks such a form, or if there isn't
	// any such definition.
	DefinitionItem* GetExprDI(const Expr* expr);

	// Returns the definition item for a given ID; creates it if
	// it doesn't already exist.
	DefinitionItem* GetID_DI(const ID* id);

	const DefinitionItem* GetConstID_DI(const ID* id) const;
	const DefinitionItem* GetConstID_DI(const DefinitionItem* di,
						const char* field_name) const;

protected:
	ID_to_DI_Map i2d;
};
