// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Tag.h"
#include "zeek/conntuple/Builder.h"
#include "zeek/conntuple/Component.h"
#include "zeek/plugin/ComponentManager.h"

namespace zeek {

namespace conntuple {

class Manager : public plugin::ComponentManager<Component> {
public:
    Manager();
    ~Manager() {};

    void InitPostScript();

    Builder& GetBuilder() { return *builder; }

private:
    BuilderPtr InstantiateBuilder(const EnumValPtr& tag);

    BuilderPtr builder; // The currently active conn tuple builder.
};

} // namespace conntuple

extern zeek::conntuple::Manager* conntuple_mgr;

} // namespace zeek
