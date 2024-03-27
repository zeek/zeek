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

SerializerComponent::SerializerComponent(const std::string& name, factory_callback arg_factory)
    : plugin::Component(plugin::component::CLUSTER_SERIALIZER, name, 0, cluster::manager->Serializers().GetTagType()) {
    factory = arg_factory;
}

void SerializerComponent::Initialize() {
    InitializeTag();
    cluster::manager->Serializers().RegisterComponent(this, "CLUSTER_SERIALIZER_");
}

void SerializerComponent::DoDescribe(ODesc* d) const {
    d->Add("Cluster::CLUSTER_SERIALIZER_");
    d->Add(CanonicalName());
}
