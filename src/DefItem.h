// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

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
	DefinitionItem* CreateField(const char* field, const BroType* t);

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
