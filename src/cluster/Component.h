// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/plugin/Component.h"

namespace zeek::cluster {

class BackendComponent : public plugin::Component {
public:
    using factory_callback = std::unique_ptr<Backend> (*)(std::unique_ptr<EventSerializer>,
                                                          std::unique_ptr<LogSerializer>,
                                                          std::unique_ptr<detail::EventHandlingStrategy>);

    /**
     * Constructor.
     *
     * @param name The name of the cluster backend. A Zeek script-level enum
     * with the name Cluster::CLUSTER_BACKEND_<NAME> will be created.
     *
     * @param factory A factory function to instantiate instances of the
     * cluster backend.
     */
    BackendComponent(const std::string& name, factory_callback factory);

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


class EventSerializerComponent : public plugin::Component {
public:
    using factory_callback = std::unique_ptr<EventSerializer> (*)();

    /**
     * Constructor.
     *
     * @param name The name of the event serializer. A Zeek script-level enum
     * with the name Cluster::EVENT_SERIALIZER_<NAME> will be created.
     *
     * @param factory A factory function to instantiate instances of the
     * event serializer.
     */
    EventSerializerComponent(const std::string& name, factory_callback factory);

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

class LogSerializerComponent : public plugin::Component {
public:
    using factory_callback = std::unique_ptr<LogSerializer> (*)();

    /**
     * Constructor.
     *
     * @param name The name of the log serializer. A Zeek script-level enum
     * with the name Cluster::LOG_SERIALIZER_<NAME> will be created.
     *
     * @param factory A factory function to instantiate instances of the
     * log serializer.
     */
    LogSerializerComponent(const std::string& name, factory_callback factory);

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
