// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <ctime> // for time_t
#include <list>
#include <string>

#include "zeek/plugin/Plugin.h"
#include "zeek/zeekygen/Info.h"

namespace zeek::zeekygen::detail {

/**
 * Information about a Spicy EVT module.
 */
class SpicyModuleInfo : public Info {
public:
    /**
     * Ctor.
     * @param name name of the Spicy EVT module.
     * @param description text describing the module further
     */
    explicit SpicyModuleInfo(std::string name, std::string description)
        : name(std::move(name)), description(std::move(description)) {}

    /** @return textual description of the module */
    const auto& Description() const { return description; }

    /**
     * @return A list of all registered components.
     */
    const auto& Components() const { return components; }

    /**
     * @return A list of all registered BiF items.
     */
    const auto& BifItems() const { return bif_items; }

    /** Register a component provided by the EVT module. */
    void AddComponent(plugin::Component* c) { components.push_back(c); }

    /** Register a BiF item provided by the EVT module. */
    void AddBifItem(const std::string& id, plugin::BifItem::Type type) { bif_items.emplace_back(id, type); }

private:
    time_t DoGetModificationTime() const override { return time(nullptr); }
    std::string DoName() const override { return name; }
    std::string DoReStructuredText(bool roles_only) const override { return ""; }

    std::string name;
    std::string description;

    std::list<plugin::Component*> components;
    std::list<plugin::BifItem> bif_items;
};

} // namespace zeek::zeekygen::detail
