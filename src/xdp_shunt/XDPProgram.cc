// See the file "COPYING" in the main distribution directory for copyright.

#include "XDPProgram.h"

#include "zeek/broker/Data.h"

zeek::OpaqueTypePtr zeek::plugin::detail::Zeek_XDP_Shunter::program_opaque;
IMPLEMENT_OPAQUE_VALUE(zeek::plugin::detail::Zeek_XDP_Shunter::XDPProgramVal)

std::optional<zeek::BrokerData> zeek::plugin::detail::Zeek_XDP_Shunter::XDPProgramVal::DoSerializeData() const {
    return {};
}

bool zeek::plugin::detail::Zeek_XDP_Shunter::XDPProgramVal::DoUnserializeData(zeek::BrokerDataView) { return false; }
