#ifndef PLUGIN_COMPONENT_MANAGER_H
#define PLUGIN_COMPONENT_MANAGER_H

#include <map>
#include <list>
#include <string>

#include "Type.h"
#include "ID.h"
#include "Var.h"
#include "Val.h"
#include "Reporter.h"
#include "broxygen/Manager.h"

namespace plugin {

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
	 * Constructor creates a new enum type called a "Tag" to associate with
	 * a component.
	 *
	 * @param module The script-layer module in which to install the "Tag" ID
	 * representing an enum type.
	 */
	ComponentManager(const string& module);

	/**
	 * @return The script-layer module in which the component's "Tag" ID lives.
	 */
	const char* GetModule() const;

	/**
	 * @return A list of all registered components.
	 */
	list<C*> GetComponents() const;

	/**
	 * @return The enum type associated with the script-layer "Tag".
	 */
	EnumType* GetTagEnumType() const;

	/**
	 * Get a component name from its tag.
	 *
	 * @param tag A component's tag.
	 * @return The canonical component name.
	 */
	const char* GetComponentName(T tag) const;

	/**
	 * Get a component name from it's enum value.
	 *
	 * @param val A component's enum value.
	 * @return The canonical component name.
	 */
	const char* GetComponentName(Val* val) const;

	/**
	 * Get a component tag from its name.
	 *
	 * @param name A component's canonical name.
	 * @return The component's tag, or a tag representing an error if
	 * no such component assoicated with the name exists.
	 */
	T GetComponentTag(const string& name) const;

	/**
	 * Get a component tag from its enum value.
	 *
	 * @param v A component's enum value.
	 * @return The component's tag, or a tag representing an error if
	 * no such component assoicated with the value exists.
	 */
	T GetComponentTag(Val* v) const;

protected:

	/**
	 * Add a component the internal maps used to keep track of it and create
	 * a script-layer ID for the component's enum value.
	 *
	 * @param component A component to track.
	 * @param prefix The script-layer ID associated with the component's enum
	 * value will be a concatenation of this prefix and the component's
	 * canonical name.
	 */
	void RegisterComponent(C* component, const string& prefix = "");

	/**
	 * @param name The canonical name of a component.
	 * @return The component associated with the name or a null pointer if no
	 * such component exists.
	 */
	C* Lookup(const string& name) const;

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

	string module; /**< Script layer module in which component tags live. */
	EnumType* tag_enum_type; /**< Enum type of component tags. */
	map<string, C*> components_by_name;
	map<T, C*> components_by_tag;
	map<int, C*> components_by_val;
};

template <class T, class C>
ComponentManager<T, C>::ComponentManager(const string& arg_module)
	: module(arg_module)
	{
	tag_enum_type = new EnumType();
	::ID* id = install_ID("Tag", module.c_str(), true, true);
	add_type(id, tag_enum_type, 0);
	broxygen_mgr->Identifier(id);
	}

template <class T, class C>
const char* ComponentManager<T, C>::GetModule() const
	{
	return module.c_str();
	}

template <class T, class C>
list<C*> ComponentManager<T, C>::GetComponents() const
	{
	list<C*> rval;
	typename map<T, C*>::const_iterator i;

	for ( i = components_by_tag.begin(); i != components_by_tag.end(); ++i )
	      rval.push_back(i->second);

	return rval;
	}

template <class T, class C>
EnumType* ComponentManager<T, C>::GetTagEnumType() const
	{
	return tag_enum_type;
	}

template <class T, class C>
const char* ComponentManager<T, C>::GetComponentName(T tag) const
	{
	static const char* error = "<error>";

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
const char* ComponentManager<T, C>::GetComponentName(Val* val) const
	{
	return GetComponentName(T(val->AsEnumVal()));
	}

template <class T, class C>
T ComponentManager<T, C>::GetComponentTag(const string& name) const
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
C* ComponentManager<T, C>::Lookup(const string& name) const
	{
	typename map<string, C*>::const_iterator i =
	        components_by_name.find(to_upper(name));
	return i != components_by_name.end() ? i->second : 0;
	}

template <class T, class C>
C* ComponentManager<T, C>::Lookup(const T& tag) const
	{
	typename map<T, C*>::const_iterator i = components_by_tag.find(tag);
	return i != components_by_tag.end() ? i->second : 0;
	}

template <class T, class C>
C* ComponentManager<T, C>::Lookup(EnumVal* val) const
	{
	typename map<int, C*>::const_iterator i =
	        components_by_val.find(val->InternalInt());
	return i != components_by_val.end() ? i->second : 0;
	}

template <class T, class C>
void ComponentManager<T, C>::RegisterComponent(C* component,
                                               const string& prefix)
	{
	const char* cname = component->CanonicalName();

	if ( Lookup(cname) )
		reporter->FatalError("Component '%s::%s' defined more than once",
		                     module.c_str(), cname);

	DBG_LOG(DBG_PLUGINS, "Registering component %s (tag %s)",
	        component->Name(), component->Tag().AsString().c_str());

	components_by_name.insert(std::make_pair(cname, component));
	components_by_tag.insert(std::make_pair(component->Tag(), component));
	components_by_val.insert(std::make_pair(
	        component->Tag().AsEnumVal()->InternalInt(), component));

	// Install an identfier for enum value
	string id = fmt("%s%s", prefix.c_str(), cname);
	tag_enum_type->AddName(module, id.c_str(),
	                       component->Tag().AsEnumVal()->InternalInt(), true);
	}

} // namespace plugin

#endif
