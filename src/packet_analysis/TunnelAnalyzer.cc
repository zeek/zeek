// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/TunnelAnalyzer.h"

#include "zeek/session/Session.h"

namespace zeek::packet_analysis {

bool TunnelAnalyzer::CheckTunnelDepth(Packet* packet) {
    if ( packet->encap && packet->encap->Depth() >= BifConst::Tunnel::max_depth ) {
        if ( packet->session )
            packet->session->CheckHistory(zeek::session::detail::HIST_ANALYZER_LIMIT_REACHED, 'X');
        Weird("exceeded_tunnel_max_depth", packet);
        return false;
    }
    return true;
}

} // namespace zeek::packet_analysis
