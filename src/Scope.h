// $Id: Scope.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef scope_h
#define scope_h

#include <string>

#include "Dict.h"
#include "Obj.h"
#include "BroList.h"
#include "TraverseTypes.h"

class ID;
class BroType;
class ListVal;

declare(PDict,ID);

class Scope : public BroObj {
public:
	Scope(ID* id);
	~Scope();

	ID* Lookup(const char* name) const	{ return local->Lookup(name); }
	void Insert(const char* name, ID* id)	{ local->Insert(name, id); }
	ID* Remove(const char* name)
		{
		HashKey key(name);
		return (ID*) local->Remove(&key);
		}

	ID* ScopeID() const		{ return scope_id; }
	BroType* ReturnType() const	{ return return_type; }

	int Length() const		{ return local->Length(); }
	PDict(ID)* Vars() const		{ return local; }

	ID* GenerateTemporary(const char* name);

	PDict(ID)* GetIDs() const	{ return local; }

	// Returns the list of variables needing initialization, and
	// removes it from this Scope.
	id_list* GetInits();

	// Adds a variable to the list.
	void AddInit(ID* id)		{ inits->append(id); }

	void Describe(ODesc* d) const;

	TraversalCode Traverse(TraversalCallback* cb) const;

protected:
	ID* scope_id;
	BroType* return_type;
	PDict(ID)* local;
	id_list* inits;
};

extern const char* GLOBAL_MODULE_NAME;

extern string extract_module_name(const char* name);
extern string normalized_module_name(const char* module_name); // w/o ::

// Concatenates module_name::var_name unless var_name is already fully
// qualified, in which case it is returned unmodified.
extern string make_full_var_name(const char* module_name, const char* var_name);

extern bool in_debug;

// If no_global is true, don't search in the default "global" namespace.
extern ID* lookup_ID(const char* name, const char* module,
			bool no_global = false);
extern ID* install_ID(const char* name, const char* module_name,
			bool is_global, bool is_export);

extern void push_scope(ID* id);
extern void push_existing_scope(Scope* scope);

// Returns the one popped off; it's not deleted.
extern Scope* pop_scope();
extern Scope* current_scope();
extern Scope* global_scope();

// Current module (identified by its name).
extern string current_module;

#endif
