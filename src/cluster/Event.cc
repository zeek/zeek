// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Event.h"

#include "zeek/Event.h"
#include "zeek/EventRegistry.h"

using namespace zeek::cluster;

double Event::Timestamp() const {
    if ( meta ) {
        for ( const auto& m : *meta ) {
            if ( m.Id() == static_cast<zeek_uint_t>(zeek::detail::MetadataType::NetworkTimestamp) )
                return m.Val()->AsTime();
        }
    }

    return zeek::detail::NO_TIMESTAMP;
}

bool Event::AddMetadata(const EnumValPtr& id, zeek::ValPtr val) {
    if ( ! id || ! val )
        return false;

    const auto* desc = zeek::event_registry->LookupMetadata(id->Get());
    if ( ! desc )
        return false;

    if ( ! same_type(val->GetType(), desc->Type()) )
        return false;

    if ( ! meta )
        meta = std::make_unique<zeek::detail::EventMetadataVector>();

    // Internally stored as zeek_uint_t for serializers.
    meta->emplace_back(desc->Id(), std::move(val));

    return true;
}

std::tuple<zeek::EventHandlerPtr, zeek::Args, zeek::detail::EventMetadataVectorPtr> Event::Take() && {
    return {handler, std::move(args), std::move(meta)};
}
