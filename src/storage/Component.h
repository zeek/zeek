// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Tag.h"
#include "zeek/Val.h"
#include "zeek/plugin/Component.h"

namespace zeek::storage {

class Backend;

/**
 * Component description for plugins providing storage backends.
 */
class Component : public plugin::Component {
public:
    using factory_callback = Backend* (*)();

    /**
     * Constructor.
     *
     * @param name The name of the provided backend. This name is used
     * across the system to identify the backend.
     *
     * @param factory A factory function to instantiate instances of the
     * backend's class, which must be derived directly or indirectly from
     * storage::Backend. This is typically a static \c Instantiate()
     * method inside the class that just allocates and returns a new
     * instance.
     */
    Component(const std::string& name, factory_callback factory);

    /**
     * Destructor.
     */
    ~Component() override = default;

    /**
     * Initialization function. This function has to be called before any
     * plugin component functionality is used; it is used to add the
     * plugin component to the list of components and to initialize tags
     */
    void Initialize() override;

    /**
     * Returns the backend's factory function.
     */
    factory_callback Factory() const { return factory; }

protected:
    /**
     * Overridden from plugin::Component.
     */
    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};

} // namespace zeek::storage
