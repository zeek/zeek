// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <string>
#include <string_view>
#include <utility>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/TraverseTypes.h"
#include "zeek/ZeekList.h"

namespace zeek
	{

class Type;
template <class T> class IntrusivePtr;
using TypePtr = IntrusivePtr<Type>;

namespace detail
	{

class Attr;
class ID;
using AttrPtr = IntrusivePtr<Attr>;
using IDPtr = IntrusivePtr<ID>;

class Scope;
using ScopePtr = IntrusivePtr<Scope>;

class Scope : public Obj
	{
public:
	explicit Scope(IDPtr id, std::unique_ptr<std::vector<AttrPtr>> al);

	const IDPtr& Find(std::string_view name) const;

	void Insert(std::string name, IDPtr id)
		{
		local[name] = id;
		ordered_vars.push_back(id);
		}

	void RemoveGlobal(std::string name, IDPtr /* gid */)
		{
		local.erase(name);

		// We could remove the identifier from ordered_vars, but for
		// now we skip doing so because (1) the only removals we do are
		// for global scope (per the method name), and the only use
		// of ordered_vars is for traversing function parameters
		// (i.e., non-global scope), and (2) it would be a pain to
		// do so given the current data structure.
		}

	const IDPtr& GetID() const { return scope_id; }

	const std::unique_ptr<std::vector<AttrPtr>>& Attrs() const { return attrs; }

	const TypePtr& GetReturnType() const { return return_type; }

	size_t Length() const { return local.size(); }
	const auto& Vars() const { return local; }
	const auto& OrderedVars() const { return ordered_vars; }

	IDPtr GenerateTemporary(const char* name);

	// Returns the list of variables needing initialization, and
	// removes it from this Scope.
	std::vector<IDPtr> GetInits();

	// Adds a variable to the list.
	void AddInit(IDPtr id) { inits.emplace_back(std::move(id)); }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const;

protected:
	IDPtr scope_id;
	std::unique_ptr<std::vector<AttrPtr>> attrs;
	TypePtr return_type;
	std::map<std::string, IDPtr, std::less<>> local;
	std::vector<IDPtr> inits;

	// We keep track of identifiers in the order that they're added.
	// This is necessary for script optimization to be able to find
	// event/hook parameters for instances where the declaration of
	// an additional handler uses different names for the parameters
	// than the original declaration.
	std::vector<IntrusivePtr<ID>> ordered_vars;
	};

// If no_global is true, don't search in the default "global" namespace.
extern const IDPtr& lookup_ID(const char* name, const char* module, bool no_global = false,
                              bool same_module_only = false, bool check_export = true);

extern IDPtr install_ID(const char* name, const char* module_name, bool is_global, bool is_export);
void remove_global_ID(const IDPtr& gid);

extern void push_scope(IDPtr id, std::unique_ptr<std::vector<AttrPtr>> attrs);
extern void push_existing_scope(ScopePtr scope);

// Returns the one popped off.
extern ScopePtr pop_scope();

extern ScopePtr current_scope();
extern ScopePtr global_scope();

// Current module (identified by its name).
extern std::string current_module;

	} // namespace detail
	} // namespace zeek

extern bool in_debug;
