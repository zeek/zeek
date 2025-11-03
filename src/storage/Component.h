// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/IntrusivePtr.h"
#include "zeek/plugin/Component.h"

namespace zeek::storage {

class Backend;
class Serializer;

/**
 * Component description for plugins providing storage backends.
 */
class BackendComponent : public plugin::Component {
public:
    using factory_callback = IntrusivePtr<Backend> (*)();

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
    BackendComponent(const std::string& name, factory_callback factory);

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

/**
 * Component description for plugins providing serialization for storage data..
 */
class SerializerComponent : public plugin::Component {
public:
    using factory_callback = std::unique_ptr<Serializer> (*)();

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
    SerializerComponent(const std::string& name, factory_callback factory);

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
