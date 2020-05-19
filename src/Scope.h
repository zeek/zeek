// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include <string>
#include <string_view>
#include <map>

#include "Obj.h"
#include "BroList.h"
#include "IntrusivePtr.h"
#include "TraverseTypes.h"

template <class T> class IntrusivePtr;
class BroType;
class ListVal;

FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);

class Scope : public BroObj {
public:
	explicit Scope(IntrusivePtr<zeek::detail::ID> id,
	               std::unique_ptr<std::vector<IntrusivePtr<Attr>>> al);

	const IntrusivePtr<zeek::detail::ID>& Find(std::string_view name) const;

	template<typename N>
	[[deprecated("Remove in v4.1.  Use Find().")]]
	zeek::detail::ID* Lookup(N&& name) const
		{ return Find(name).get(); }

	template<typename N, typename I>
	void Insert(N&& name, I&& id) { local[std::forward<N>(name)] = std::forward<I>(id); }

	IntrusivePtr<zeek::detail::ID> Remove(std::string_view name);

	[[deprecated("Remove in v4.1.  Use GetID().")]]
	zeek::detail::ID* ScopeID() const		{ return scope_id.get(); }

	const IntrusivePtr<zeek::detail::ID>& GetID() const
		{ return scope_id; }

	const std::unique_ptr<std::vector<IntrusivePtr<Attr>>>& Attrs() const
		{ return attrs; }

	[[deprecated("Remove in v4.1.  Use GetReturnTrype().")]]
	BroType* ReturnType() const	{ return return_type.get(); }

	const IntrusivePtr<BroType>& GetReturnType() const
		{ return return_type; }

	size_t Length() const		{ return local.size(); }
	const auto& Vars()	{ return local; }

	IntrusivePtr<zeek::detail::ID> GenerateTemporary(const char* name);

	// Returns the list of variables needing initialization, and
	// removes it from this Scope.
	std::vector<IntrusivePtr<zeek::detail::ID>> GetInits();

	// Adds a variable to the list.
	void AddInit(IntrusivePtr<zeek::detail::ID> id)
		{ inits.emplace_back(std::move(id)); }

	void Describe(ODesc* d) const override;

	TraversalCode Traverse(TraversalCallback* cb) const;

protected:
	IntrusivePtr<zeek::detail::ID> scope_id;
	std::unique_ptr<std::vector<IntrusivePtr<Attr>>> attrs;
	IntrusivePtr<BroType> return_type;
	std::map<std::string, IntrusivePtr<zeek::detail::ID>, std::less<>> local;
	std::vector<IntrusivePtr<zeek::detail::ID>> inits;
};


extern bool in_debug;

// If no_global is true, don't search in the default "global" namespace.
extern const IntrusivePtr<zeek::detail::ID>& lookup_ID(const char* name, const char* module,
                                                       bool no_global = false,
                                                       bool same_module_only = false,
                                                       bool check_export = true);

extern IntrusivePtr<zeek::detail::ID> install_ID(const char* name, const char* module_name,
                                                 bool is_global, bool is_export);

extern void push_scope(IntrusivePtr<zeek::detail::ID> id,
                       std::unique_ptr<std::vector<IntrusivePtr<Attr>>> attrs);
extern void push_existing_scope(Scope* scope);

// Returns the one popped off.
extern IntrusivePtr<Scope> pop_scope();
extern Scope* current_scope();
extern Scope* global_scope();

// Current module (identified by its name).
extern std::string current_module;
