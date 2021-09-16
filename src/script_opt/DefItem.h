// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/ID.h"
#include "zeek/Type.h"
#include "zeek/script_opt/DefPoint.h"

namespace zeek::detail
	{

// A definition item is a Zeek script entity that can be assigned to.
// Currently, we track variables and record fields; the latter can
// be nested (for example, a field that's in a record that itself is
// a field in another record).  In principle we could try to track
// table or vector elements, but that's only going to be feasible for
// constant indices, so presumably not much bang-for-the-buck.
//
// For script optimization, we only need to track variables, and we could
// considerably simplify the code by doing so.  However, there's long
// been a desire to be able to statically determine that a record field
// will be used without first having been set, hence we go the more
// complicated route here.

class DefinitionItem
	{
public:
	// Constructor for the simple case of tracking assignments to
	// a variable.
	DefinitionItem(const ID* _id);

	// The more complicated case of assigning to a field in a record
	// (which itself might be a field in a record).
	DefinitionItem(const DefinitionItem* _di, const char* _field_name, TypePtr _t);

	const char* Name() const { return name.c_str(); }

	TypePtr GetType() const { return t; }
	bool IsRecord() const { return t->Tag() == TYPE_RECORD; }

	// The identifier to which this item ultimately belongs.
	const ID* RootID() const { return di ? di->RootID() : id; }

	// For this definition item, look for a field corresponding
	// to the given name or offset.  Nil if the field has not (yet)
	// been created.
	std::shared_ptr<DefinitionItem> FindField(const char* field) const;
	std::shared_ptr<DefinitionItem> FindField(int offset) const;

	// Start tracking a field in this definition item with the
	// given name or offset, returning the associated item.
	//
	// If the field already exists, then it's simply returned.
	std::shared_ptr<DefinitionItem> CreateField(const char* field, TypePtr t);
	std::shared_ptr<DefinitionItem> CreateField(int offset, TypePtr t);

protected:
	void CheckForRecord();

	bool is_id;
	const ID* id;
	const DefinitionItem* di;
	const char* field_name;

	TypePtr t;
	std::string name;

	const RecordType* rt;

	// If present, tracks definition items for a record's fields as
	// these are seen (i.e., as they are entered via CreateField()).
	std::optional<std::vector<std::shared_ptr<DefinitionItem>>> fields;
	int num_fields;
	};

// For a given identifier, locates its associated definition item.
typedef std::unordered_map<const ID*, std::shared_ptr<DefinitionItem>> ID_to_DI_Map;

// Class for managing a set of IDs and their associated definition items.
class DefItemMap
	{
public:
	// Gets the definition for either a name or a record field reference.
	// Returns nil if "expr" lacks such a form, or if there isn't
	// any such definition.
	std::shared_ptr<DefinitionItem> GetExprDI(const Expr* expr);

	// Returns the definition item for a given ID; creates it if
	// it doesn't already exist.
	std::shared_ptr<DefinitionItem> GetID_DI(const ID* id);

	// Returns the definition item for a given ID, or nil if it
	// doesn't exist.
	const DefinitionItem* GetConstID_DI(const ID* id) const;

	// The same for a record field for a given definition item.
	const DefinitionItem* GetConstID_DI(const DefinitionItem* di, const char* field_name) const;

protected:
	ID_to_DI_Map i2d;
	};

	} // zeek::detail
