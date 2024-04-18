// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/plugin/Component.h"

namespace zeek::cluster {

class BackendComponent : public plugin::Component {
public:
    using factory_callback = Backend* (*)(Serializer*);

    /**
     * Constructor.
     *
     * @param name The name of cluster backend. An Zeek script level enum
     * with the name Cluster::CLUSTER_BACKEND_<NAME> will be created.
     *
     * @param factory A factory function to instantiate instances of the
     * cluster backend.
     */
    BackendComponent(const std::string& name, factory_callback factory);

    /**
     * Destructor.
     */
    ~BackendComponent() override = default;

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
    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};


class SerializerComponent : public plugin::Component {
public:
    using factory_callback = Serializer* (*)();

    /**
     * Constructor.
     *
     * @param name The name of cluster backend. An Zeek script level enum
     * with the name Cluster::EVENT_SERIALIZER_<NAME> will be created.
     *
     * @param factory A factory function to instantiate instances of the
     * cluster backend.
     */
    SerializerComponent(const std::string& name, factory_callback factory);

    /**
     * Destructor.
     */
    ~SerializerComponent() override = default;

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
    void DoDescribe(ODesc* d) const override;

private:
    factory_callback factory;
};
} // namespace zeek::cluster
