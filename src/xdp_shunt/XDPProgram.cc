#include "XDPProgram.h"

#include <zeek/broker/Data.h>

zeek::OpaqueTypePtr xdp::shunter::detail::program_opaque;
IMPLEMENT_OPAQUE_VALUE(xdp::shunter::detail::XDPProgramVal)

std::optional<zeek::BrokerData> xdp::shunter::detail::XDPProgramVal::DoSerializeData() const { return {}; }

bool xdp::shunter::detail::XDPProgramVal::DoUnserializeData(zeek::BrokerDataView) { return false; }
