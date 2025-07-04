// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Tag.h"
#include "zeek/conn_key/Component.h"
#include "zeek/conn_key/Factory.h"
#include "zeek/plugin/Component.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek {

namespace conn_key {

/**
 * This component manager is for registration of pluggable ConnKey factories
 * that provide a zeek::plugin::component::CONNKEY component.
 */
class Manager : public plugin::ComponentManager<conn_key::Component> {
public:
    /**
     * Constructor.
     */
    Manager();

    /**
     * Destructor.
     */
    ~Manager() = default;

    /**
     * Hook called during Zeek's startup sequence at InitPostScript() time.
     */
    void InitPostScript();

    /**
     * Return the instantiated Factory selected by the @c ConnKey::factory script-level variable.
     *
     * @return A reference to the selected see Factory.
     */
    Factory& GetFactory() { return *factory; }

private:
    /**
     * @return A pointer to a Factory given @arg tag.
     */
    FactoryPtr InstantiateFactory(const EnumValPtr& tag);

    FactoryPtr factory;
};

} // namespace conn_key

extern zeek::conn_key::Manager* conn_key_mgr;


} // namespace zeek
