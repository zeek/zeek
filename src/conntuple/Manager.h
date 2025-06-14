// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Tag.h"
#include "zeek/conntuple/Component.h"
#include "zeek/conntuple/Factory.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek {

namespace conntuple {

class Manager : public plugin::ComponentManager<Component> {
public:
    Manager();
    ~Manager() {};

    void InitPostScript();

    Factory& GetFactory() { return *factory; }

private:
    FactoryPtr InstantiateFactory(const EnumValPtr& tag);

    FactoryPtr factory;
};

} // namespace conntuple

extern zeek::conntuple::Manager* conntuple_mgr;

} // namespace zeek
