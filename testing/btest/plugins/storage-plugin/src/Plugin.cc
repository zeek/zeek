#include "Plugin.h"

#include "zeek/storage/Component.h"

#include "StorageDummy.h"

namespace btest::plugin::Testing_StorageDummy {
Plugin plugin;
}

using namespace btest::plugin::Testing_StorageDummy;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(
        new zeek::storage::BackendComponent("StorageDummy", btest::storage::backend::StorageDummy::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Testing::StorageDummy";
    config.description = "A dummy storage plugin";
    config.version.major = 1;
    config.version.minor = 0;
    config.version.patch = 0;
    return config;
}
