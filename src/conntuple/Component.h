// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <functional>
#include <memory>

#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"

namespace zeek::conntuple {

class Builder;
using BuilderPtr = std::unique_ptr<Builder>;

class Component : public plugin::Component {
public:
    using factory_callback = std::function<BuilderPtr()>;

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
    factory_callback factory; // The tuple builder's factory callback.
};

} // namespace zeek::conntuple
