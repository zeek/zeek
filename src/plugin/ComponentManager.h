#pragma once

#include <list>
#include <map>
#include <string>

#include "zeek/Attr.h"
#include "zeek/DebugLogger.h"
#include "zeek/Expr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Tag.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/Var.h" // for add_type()
#include "zeek/ZeekString.h"
#include "zeek/module_util.h"
#include "zeek/zeekygen/Manager.h"

namespace zeek::plugin {

/**
 * A class that manages tracking of plugin components (e.g. analyzers) and
 * installs identifiers in the script-layer to identify them by a unique tag,
 * (a script-layer enum value).
 *
 * @tparam C A plugin::Component type derivative.
 */
template<class C>
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
    ComponentManager(const std::string& module, const std::string& local_id, const std::string& parent_module = "");

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
    const EnumTypePtr& GetTagType() const;

    /**
     * Get a component name from its tag.
     *
     * @param tag A component's tag.
     * @return The canonical component name.
     */
    const std::string& GetComponentName(zeek::Tag tag) const;

    /**
     * Get a component name from it's enum value.
     *
     * @param val A component's enum value.
     * @return The canonical component name.
     */
    const std::string& GetComponentName(EnumValPtr val) const;

    /**
     * Get a component name from its tag.
     *
     * @param tag A component's tag.
     * @return The canonical component name as a StringValPtr.
     */
    StringValPtr GetComponentNameVal(zeek::Tag tag) const;

    /**
     * Get a component name from it's enum value.
     *
     * @param val A component's enum value.
     * @return The canonical component name as a StringValPtr.
     */
    StringValPtr GetComponentNameVal(EnumValPtr val) const;

    /**
     * Get a component tag from its name.
     *
     * @param name A component's canonical name.
     * @return The component's tag, or a tag representing an error if
     * no such component associated with the name exists.
     */
    zeek::Tag GetComponentTag(const std::string& name) const;

    /**
     * Get a component tag from its enum value.
     *
     * @param v A component's enum value.
     * @return The component's tag, or a tag representing an error if
     * no such component associated with the value exists.
     */
    zeek::Tag GetComponentTag(Val* v) const;

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
     * @param consider_remappings If true, component mappings will be honored
     * if the original component is disabled.
     * @return The component associated with the name or a null pointer if no
     * such component exists.
     */
    C* Lookup(const std::string& name, bool consider_remappings = true) const;

    /**
     * @param name A component tag.
     * @param consider_remappings If true, component mappings will be honored
     * if the original component is disabled.
     * @return The component associated with the tag or a null pointer if no
     * such component exists.
     */
    C* Lookup(const zeek::Tag& tag, bool consider_remappings = true) const;

    /**
     * @param val A component's enum value.
     * @param consider_remappings If true, component mappings will be honored
     * if the original component is disabled.
     * @return The component associated with the value or a null pointer if no
     * such component exists.
     */
    C* Lookup(EnumVal* val, bool consider_remappings = true) const;

    /**
     * @param val A component's enum value.
     * @param consider_remappings If true, component mappings will be honored
     * if the original component is disabled.
     * @return The component associated with the value or a null pointer if no
     * such component exists.
     */
    C* Lookup(const EnumValPtr& val, bool consider_remappings = true) const;

    /**
     * Registers a mapping of a component to another one that will be honored
     * by the `Lookup()` methods if (and only if) the original is currently
     * disabled.
     *
     * @param old The original component tag.
     * @param new_ The new component tag.
     */
    void AddComponentMapping(const zeek::Tag& old, const zeek::Tag& new_) {
        if ( old != new_ ) {
            component_mapping_by_src[old] = new_;
            component_mapping_by_dst[new_] = old;
        }
    }

    /**
     * Returns true if a given component has a mapping to different one in place.
     *
     * @param tag The component tag to check.
     */
    auto HasComponentMapping(const zeek::Tag& tag) const { return component_mapping_by_src.count(tag); }

    /**
     * Returns true if a given component is mapped to from a different one.
     *
     * @param tag The component tag to check.
     */
    bool ProvidesComponentMapping(const zeek::Tag& tag) const { return component_mapping_by_dst.count(tag); }

private:
    /** Script layer module in which component tags live. */
    std::string module;
    std::string parent_module;

    /** Module-local type of component tags. */
    EnumTypePtr tag_enum_type;
    EnumTypePtr parent_tag_enum_type;

    std::map<std::string, C*> components_by_name;
    std::map<zeek::Tag, C*> components_by_tag;
    std::map<zeek_int_t, C*> components_by_val;
    std::map<zeek::Tag, zeek::Tag> component_mapping_by_src;
    std::map<zeek::Tag, zeek::Tag> component_mapping_by_dst;
};

template<class C>
ComponentManager<C>::ComponentManager(const std::string& module, const std::string& local_id,
                                      const std::string& parent_module)
    : module(module), parent_module(parent_module) {
    tag_enum_type = make_intrusive<EnumType>(module + "::" + local_id);
    auto id = zeek::detail::install_ID(local_id.c_str(), module.c_str(), true, true);
    zeek::detail::add_type(id.get(), tag_enum_type, nullptr);
    zeek::detail::zeekygen_mgr->Identifier(std::move(id));

    if ( ! parent_module.empty() ) {
        // check to see if the parent module's type has been created already
        id = zeek::detail::lookup_ID(local_id.c_str(), parent_module.c_str(), false, true, false);
        if ( id != zeek::detail::ID::nil ) {
            parent_tag_enum_type = id->GetType<EnumType>();
        }
        else {
            parent_tag_enum_type = make_intrusive<EnumType>(parent_module + "::" + local_id);
            id = zeek::detail::install_ID(local_id.c_str(), parent_module.c_str(), true, true);
            zeek::detail::add_type(id.get(), parent_tag_enum_type, nullptr);
            zeek::detail::zeekygen_mgr->Identifier(std::move(id));
        }
    }
}

template<class C>
const std::string& ComponentManager<C>::GetModule() const {
    return module;
}

template<class C>
std::list<C*> ComponentManager<C>::GetComponents() const {
    std::list<C*> rval;
    typename std::map<zeek::Tag, C*>::const_iterator i;

    for ( i = components_by_tag.begin(); i != components_by_tag.end(); ++i )
        rval.push_back(i->second);

    return rval;
}

template<class C>
const EnumTypePtr& ComponentManager<C>::GetTagType() const {
    return tag_enum_type;
}

template<class C>
const std::string& ComponentManager<C>::GetComponentName(zeek::Tag tag) const {
    static const std::string error = "<error>";

    if ( ! tag )
        return error;

    if ( C* c = Lookup(tag, false) ) // use actual, not remapped name
        return c->CanonicalName();

    reporter->InternalWarning("requested name of unknown component tag %s", tag.AsString().c_str());
    return error;
}

template<class C>
const std::string& ComponentManager<C>::GetComponentName(EnumValPtr val) const {
    static const std::string error = "<error>";

    if ( ! val )
        return error;

    if ( C* c = Lookup(val.get()) )
        return c->CanonicalName();

    reporter->InternalWarning("requested name of unknown component tag %s", val->AsString()->CheckString());
    return error;
}

template<class C>
StringValPtr ComponentManager<C>::GetComponentNameVal(zeek::Tag tag) const {
    static auto error = make_intrusive<StringVal>("<error>");

    if ( ! tag )
        return error;

    if ( C* c = Lookup(tag) )
        return c->CanonicalNameVal();

    reporter->InternalWarning("requested name of unknown component tag %s", tag.AsString().c_str());
    return error;
}

template<class C>
StringValPtr ComponentManager<C>::GetComponentNameVal(EnumValPtr val) const {
    static auto error = make_intrusive<StringVal>("<error>");

    if ( ! val )
        return error;

    if ( C* c = Lookup(val.get()) )
        return c->CanonicalNameVal();

    reporter->InternalWarning("requested name of unknown component tag %s", val->AsString()->CheckString());
    return error;
}

template<class C>
zeek::Tag ComponentManager<C>::GetComponentTag(const std::string& name) const {
    C* c = Lookup(name);
    return c ? c->Tag() : zeek::Tag();
}

template<class C>
zeek::Tag ComponentManager<C>::GetComponentTag(Val* v) const {
    C* c = Lookup(v->AsEnumVal());
    return c ? c->Tag() : zeek::Tag();
}

template<class C>
C* ComponentManager<C>::Lookup(const std::string& name, bool consider_remappings) const {
    if ( auto i = components_by_name.find(util::to_upper(name)); i != components_by_name.end() ) {
        auto c = (*i).second;
        if ( consider_remappings && ! c->Enabled() ) {
            if ( auto j = component_mapping_by_src.find(c->Tag()); j != component_mapping_by_src.end() )
                return Lookup(j->second, false);
        }

        return c;
    }
    else
        return nullptr;
}

template<class C>
C* ComponentManager<C>::Lookup(const zeek::Tag& tag, bool consider_remappings) const {
    if ( auto i = components_by_tag.find(tag); i != components_by_tag.end() ) {
        auto c = (*i).second;
        if ( consider_remappings && ! c->Enabled() ) {
            if ( auto j = component_mapping_by_src.find(c->Tag()); j != component_mapping_by_src.end() )
                return Lookup(j->second, false);
        }

        return c;
    }
    else
        return nullptr;
}

template<class C>
C* ComponentManager<C>::Lookup(EnumVal* val, bool consider_remappings) const {
    if ( auto i = components_by_val.find(val->InternalInt()); i != components_by_val.end() ) {
        auto c = (*i).second;
        if ( consider_remappings && ! c->Enabled() ) {
            if ( auto j = component_mapping_by_src.find(c->Tag()); j != component_mapping_by_src.end() )
                return Lookup(j->second, false);
        }

        return c;
    }
    else
        return nullptr;
}

template<class C>
C* ComponentManager<C>::Lookup(const EnumValPtr& val, bool consider_remappings) const {
    return Lookup(val.get(), consider_remappings);
}

template<class C>
void ComponentManager<C>::RegisterComponent(C* component, const std::string& prefix) {
    std::string cname = component->CanonicalName();

    if ( Lookup(cname) )
        reporter->FatalError("Component '%s::%s' defined more than once", module.c_str(), cname.c_str());

    DBG_LOG(DBG_PLUGINS, "Registering component %s (tag %s)", component->Name().c_str(),
            component->Tag().AsString().c_str());

    components_by_name.insert(std::make_pair(cname, component));
    components_by_tag.insert(std::make_pair(component->Tag(), component));
    components_by_val.insert(std::make_pair(component->Tag().AsVal()->InternalInt(), component));

    // Install an identifier for enum value
    std::string id = util::fmt("%s%s", prefix.c_str(), cname.c_str());
    tag_enum_type->AddName(module, id.c_str(), component->Tag().AsVal()->InternalInt(), true, nullptr);

    if ( parent_tag_enum_type ) {
        std::string parent_id = util::fmt("%s_%s", util::strtoupper(module).c_str(), id.c_str());
        parent_tag_enum_type->AddName(parent_module, parent_id.c_str(), component->Tag().AsVal()->InternalInt(), true,
                                      nullptr);
    }
}

} // namespace zeek::plugin
