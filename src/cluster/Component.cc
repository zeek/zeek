// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Component.h"

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Tag.h"
#include "zeek/cluster/Manager.h"
#include "zeek/util.h"

using namespace zeek::cluster;

BackendComponent::BackendComponent(const std::string& name, factory_callback arg_factory)
    : plugin::Component(plugin::component::CLUSTER_BACKEND, name, 0, cluster::manager->Backends().GetTagType()) {
    factory = arg_factory;
}

void BackendComponent::Initialize() {
    InitializeTag();
    cluster::manager->Backends().RegisterComponent(this, "CLUSTER_BACKEND_");
}

void BackendComponent::DoDescribe(ODesc* d) const {
    d->Add("Cluster::CLUSTER_BACKEND_");
    d->Add(CanonicalName());
}

EventSerializerComponent::EventSerializerComponent(const std::string& name, factory_callback arg_factory)
    : plugin::Component(plugin::component::EVENT_SERIALIZER, name, 0,
                        cluster::manager->EventSerializers().GetTagType()) {
    factory = arg_factory;
}

void EventSerializerComponent::Initialize() {
    InitializeTag();
    cluster::manager->EventSerializers().RegisterComponent(this, "EVENT_SERIALIZER_");
}

void EventSerializerComponent::DoDescribe(ODesc* d) const {
    d->Add("Cluster::EVENT_SERIALIZER_");
    d->Add(CanonicalName());
}

LogSerializerComponent::LogSerializerComponent(const std::string& name, factory_callback arg_factory)
    : plugin::Component(plugin::component::LOG_SERIALIZER, name, 0, cluster::manager->LogSerializers().GetTagType()) {
    factory = arg_factory;
}

void LogSerializerComponent::Initialize() {
    InitializeTag();
    cluster::manager->EventSerializers().RegisterComponent(this, "LOG_SERIALIZER_");
}

void LogSerializerComponent::DoDescribe(ODesc* d) const {
    d->Add("Cluster::LOG_SERIALIZER_");
    d->Add(CanonicalName());
}
