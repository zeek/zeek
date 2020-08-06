#pragma once

#include <map>
#include <list>
#include <string>

#include "Type.h"
#include "Var.h" // for add_type()
#include "Val.h"
#include "Reporter.h"
#include "Scope.h"
#include "zeekygen/Manager.h"
#include "DebugLogger.h"

namespace zeek::plugin {

/**
 * A class that manages tracking of plugin components (e.g. analyzers) and
 * installs identifiers in the script-layer to identify them by a unique tag,
 * (a script-layer enum value).
 *
 * @tparam T A ::Tag type or derivative.
 * @tparam C A plugin::TaggedComponent type derivative.
 */
template <class T, class C>
class ComponentManager {
public:

	/**
	 * Constructor creates a new enum type to associate with
	 * a component.
	 *
	 * @param module The script-layer module in which to install the ID
	 * representing an enum type.
	 *
	 * @param local_id The local part of the ID of the new enum type
	 * (e.g., "Tag").
	 */
	ComponentManager(const std::string& module, const std::string& local_id);

	/**
	 * @return The script-layer module in which the component's "Tag" ID lives.
	 */
	const std::string& GetModule() const;

	/**
	 * @return A list of all registered components.
	 */
	std::list<C*> GetComponents() const;

	/**
	 * @return The enum type associated with the script-layer "Tag".
	 */
	const zeek::EnumTypePtr& GetTagType() const;

	[[deprecated("Remove in v4.1.  Use GetTagType() instead.")]]
	zeek::EnumType* GetTagEnumType() const;

	/**
	 * Get a component name from its tag.
	 *
	 * @param tag A component's tag.
	 * @return The canonical component name.
	 */
	const std::string& GetComponentName(T tag) const;

	/**
	 * Get a component name from it's enum value.
	 *
	 * @param val A component's enum value.
	 * @return The canonical component name.
	 */
	const std::string& GetComponentName(EnumValPtr val) const;

	[[deprecated("Remove in v4.1.  Use IntrusivePtr argument instead.")]]
	const std::string& GetComponentName(Val* val) const;

	/**
	 * Get a component tag from its name.
	 *
	 * @param name A component's canonical name.
	 * @return The component's tag, or a tag representing an error if
	 * no such component assoicated with the name exists.
	 */
	T GetComponentTag(const std::string& name) const;

	/**
	 * Get a component tag from its enum value.
	 *
	 * @param v A component's enum value.
	 * @return The component's tag, or a tag representing an error if
	 * no such component assoicated with the value exists.
	 */
	T GetComponentTag(Val* v) const;

	/**
	 * Add a component the internal maps used to keep track of it and create
	 * a script-layer ID for the component's enum value.
	 *
	 * @param component A component to track.
	 * @param prefix The script-layer ID associated with the component's enum
	 * value will be a concatenation of this prefix and the component's
	 * canonical name.
	 */
	void RegisterComponent(C* component, const std::string& prefix = "");

	/**
	 * @param name The canonical name of a component.
	 * @return The component associated with the name or a null pointer if no
	 * such component exists.
	 */
	C* Lookup(const std::string& name) const;

	/**
	 * @param name A component tag.
	 * @return The component associated with the tag or a null pointer if no
	 * such component exists.
	 */
	C* Lookup(const T& tag) const;

	/**
	 * @param name A component's enum value.
	 * @return The component associated with the value or a null pointer if no
	 * such component exists.
	 */
	C* Lookup(EnumVal* val) const;

private:
	std::string module; /**< Script layer module in which component tags live. */
	zeek::EnumTypePtr tag_enum_type; /**< Enum type of component tags. */
	std::map<std::string, C*> components_by_name;
	std::map<T, C*> components_by_tag;
	std::map<int, C*> components_by_val;
};

template <class T, class C>
ComponentManager<T, C>::ComponentManager(const std::string& arg_module, const std::string& local_id)
	: module(arg_module),
	  tag_enum_type(zeek::make_intrusive<zeek::EnumType>(module + "::" + local_id))
	{
	auto id = zeek::detail::install_ID(local_id.c_str(), module.c_str(), true, true);
	add_type(id.get(), tag_enum_type, nullptr);
	zeekygen_mgr->Identifier(std::move(id));
	}

template <class T, class C>
const std::string& ComponentManager<T, C>::GetModule() const
	{
	return module;
	}

template <class T, class C>
std::list<C*> ComponentManager<T, C>::GetComponents() const
	{
	std::list<C*> rval;
	typename std::map<T, C*>::const_iterator i;

	for ( i = components_by_tag.begin(); i != components_by_tag.end(); ++i )
	      rval.push_back(i->second);

	return rval;
	}

template <class T, class C>
const zeek::EnumTypePtr& ComponentManager<T, C>::GetTagType() const
	{
	return tag_enum_type;
	}

template <class T, class C>
zeek::EnumType* ComponentManager<T, C>::GetTagEnumType() const
	{
	return tag_enum_type.get();
	}

template <class T, class C>
const std::string& ComponentManager<T, C>::GetComponentName(T tag) const
	{
	static const std::string error = "<error>";

	if ( ! tag )
		return error;

	C* c = Lookup(tag);

	if ( c )
		return c->CanonicalName();

	reporter->InternalWarning("requested name of unknown component tag %s",
		                      tag.AsString().c_str());
	return error;
	}

template <class T, class C>
const std::string& ComponentManager<T, C>::GetComponentName(EnumValPtr val) const
	{
	return GetComponentName(T(std::move(val)));
	}

template <class T, class C>
const std::string& ComponentManager<T, C>::GetComponentName(Val* val) const
	{
	return GetComponentName(T({zeek::NewRef{}, val->AsEnumVal()}));
	}

template <class T, class C>
T ComponentManager<T, C>::GetComponentTag(const std::string& name) const
	{
	C* c = Lookup(name);
	return c ? c->Tag() : T();
	}

template <class T, class C>
T ComponentManager<T, C>::GetComponentTag(Val* v) const
	{
	C* c = Lookup(v->AsEnumVal());
	return c ? c->Tag() : T();
	}

template <class T, class C>
C* ComponentManager<T, C>::Lookup(const std::string& name) const
	{
	typename std::map<std::string, C*>::const_iterator i =
		components_by_name.find(zeek::util::to_upper(name));
	return i != components_by_name.end() ? i->second : 0;
	}

template <class T, class C>
C* ComponentManager<T, C>::Lookup(const T& tag) const
	{
	typename std::map<T, C*>::const_iterator i = components_by_tag.find(tag);
	return i != components_by_tag.end() ? i->second : 0;
	}

template <class T, class C>
C* ComponentManager<T, C>::Lookup(EnumVal* val) const
	{
	typename std::map<int, C*>::const_iterator i =
	        components_by_val.find(val->InternalInt());
	return i != components_by_val.end() ? i->second : 0;
	}

template <class T, class C>
void ComponentManager<T, C>::RegisterComponent(C* component,
                                               const std::string& prefix)
	{
	std::string cname = component->CanonicalName();

	if ( Lookup(cname) )
		reporter->FatalError("Component '%s::%s' defined more than once",
		                     module.c_str(), cname.c_str());

	DBG_LOG(zeek::DBG_PLUGINS, "Registering component %s (tag %s)",
	        component->Name().c_str(), component->Tag().AsString().c_str());

	components_by_name.insert(std::make_pair(cname, component));
	components_by_tag.insert(std::make_pair(component->Tag(), component));
	components_by_val.insert(std::make_pair(
	        component->Tag().AsVal()->InternalInt(), component));

	// Install an identfier for enum value
	std::string id = zeek::util::fmt("%s%s", prefix.c_str(), cname.c_str());
	tag_enum_type->AddName(module, id.c_str(),
	                       component->Tag().AsVal()->InternalInt(), true,
	                       nullptr);
	}

} // namespace plugin

namespace plugin {
	template <class T, class C>
	using ComponentManager [[deprecated("Remove in v4.1. Use zeek::plugin::ComponentManager instead.")]] =
		zeek::plugin::ComponentManager<T, C>;
}
