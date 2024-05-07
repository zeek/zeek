// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/Component.h"

#include "zeek/Desc.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Manager.h"

using namespace zeek::packet_analysis;

Component::Component(const std::string& name, factory_callback arg_factory, Tag::subtype_t arg_subtype)
    : plugin::Component(plugin::component::PACKET_ANALYZER, name, arg_subtype, packet_mgr->GetTagType()),
      factory(std::move(arg_factory)) {}

void Component::Initialize() {
    InitializeTag();
    packet_mgr->RegisterComponent(this, "ANALYZER_");
}

void Component::SetEnabled(bool arg_enabled) {
    auto analyzer = packet_mgr->GetAnalyzer(Tag().AsVal().get());
    if ( analyzer ) {
        // We can only toggle the analyzer if it's not replacing another one,
        // otherwise our dispatching tables would be wrong.
        if ( packet_mgr->ProvidesComponentMapping(Tag()) ) {
            reporter->Warning(
                "attempt to toggle packet analyzer %s, which replaces another one; toggling replacement analyzers is "
                "not supported",
                analyzer->GetAnalyzerName());
            return;
        }

        // Update the existing analyzer's state.
        analyzer->SetEnabled(arg_enabled);
    }

    plugin::Component::SetEnabled(arg_enabled);
}

void Component::DoDescribe(ODesc* d) const {
    if ( factory ) {
        d->Add("ANALYZER_");
        d->Add(CanonicalName());
        d->Add(", ");
    }

    d->Add(Enabled() ? "enabled" : "disabled");
}
