// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/storage/Component.h"

#include "zeek/Desc.h"
#include "zeek/storage/Manager.h"

namespace zeek::storage {

BackendComponent::BackendComponent(const std::string& name, factory_callback arg_factory)
    : plugin::Component(plugin::component::STORAGE_BACKEND, name, 0, storage_mgr->BackendMgr().GetTagType()) {
    factory = arg_factory;
}

void BackendComponent::Initialize() {
    InitializeTag();
    storage_mgr->BackendMgr().RegisterComponent(this, "STORAGE_BACKEND_");
}

void BackendComponent::DoDescribe(ODesc* d) const {
    d->Add("Storage::STORAGE_BACKEND_");
    d->Add(CanonicalName());
}

SerializerComponent::SerializerComponent(const std::string& name, factory_callback arg_factory)
    : plugin::Component(plugin::component::STORAGE_SERIALIZER, name, 0, storage_mgr->SerializerMgr().GetTagType()) {
    factory = arg_factory;
}

void SerializerComponent::Initialize() {
    InitializeTag();
    storage_mgr->SerializerMgr().RegisterComponent(this, "STORAGE_SERIALIZER_");
}

void SerializerComponent::DoDescribe(ODesc* d) const {
    d->Add("Storage::STORAGE_SERIALIZER_");
    d->Add(CanonicalName());
}

} // namespace zeek::storage
