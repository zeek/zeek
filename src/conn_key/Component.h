// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <functional>
#include <memory>

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek::conn_key {

class Factory;
using FactoryPtr = std::unique_ptr<Factory>;

class Component : public plugin::Component {
public:
    using factory_callback = std::function<FactoryPtr()>;

    Component(const std::string& name, factory_callback factory, zeek::Tag::subtype_t subtype = 0);
    ~Component() override = default;

    /**
     * Initialization function. This function has to be called before any
     * plugin component functionality is used; it is used to add the
     * plugin component to the list of components and to initialize tags
     */
    void Initialize() override;

    /**
     * Returns the analyzer's factory function.
     */
    factory_callback Factory() const { return factory; }

protected:
    /**
     * Overridden from plugin::Component.
     */
    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory; // The tuple factory's factory callback.
};

} // namespace zeek::conn_key
