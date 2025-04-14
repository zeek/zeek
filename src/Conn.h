// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <string>
#include <tuple>
#include <type_traits>

#include "zeek/IPAddr.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Rule.h"
#include "zeek/Tag.h"
#include "zeek/Timer.h"
#include "zeek/UID.h"
#include "zeek/WeirdState.h"
#include "zeek/ZeekArgs.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/Packet.h"
#include "zeek/session/Session.h"

namespace zeek {

class Connection;
class EncapsulationStack;
class Val;
class RecordVal;

using ValPtr = IntrusivePtr<Val>;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace session {
class Manager;
}
namespace detail {

class Specific_RE_Matcher;
class RuleEndpointState;
class RuleHdrTest;

} // namespace detail

namespace analyzer {
class Analyzer;
}
namespace packet_analysis::IP {
class SessionAdapter;
}

enum ConnEventToFlag {
    NUL_IN_LINE,
    SINGULAR_CR,
    SINGULAR_LF,
    NUM_EVENTS_TO_FLAG,
};

struct ConnTuple {
    virtual ~ConnTuple() {}

    IPAddr src_addr;
    IPAddr dst_addr;
    uint32_t src_port = 0;
    uint32_t dst_port = 0;
    uint16_t proto = UNKNOWN_IP_PROTO;
    bool is_one_way = false; // if true, don't canonicalize order
};

using ConnTuplePtr = std::shared_ptr<ConnTuple>;

static inline int addr_port_canon_lt(const IPAddr& addr1, uint32_t p1, const IPAddr& addr2, uint32_t p2) {
    return addr1 < addr2 || (addr1 == addr2 && p1 < p2);
}

class Connection final : public session::Session {
public:
    Connection(const detail::ConnKeyPtr k, double t, const ConnTuple* id, uint32_t flow, const Packet* pkt);
    Connection(const detail::ConnKey& k, double t, const ConnTuple* id, uint32_t flow, const Packet* pkt);
    ~Connection() override;

    /**
     * Invoked when an encapsulation is discovered. It records the encapsulation
     * with the connection and raises a "tunnel_changed" event if it's different
     * from the previous encapsulation or if it's the first one encountered.
     *
     * @param encap The new encapsulation. Can be set to null to indicated no
     * encapsulation or clear an old one.
     */
    void CheckEncapsulation(const std::shared_ptr<EncapsulationStack>& encap);

    /**
     * Invoked when the session is about to be removed. Use Ref(this)
     * inside Done to keep the session object around, though it'll
     * no longer be accessible from the SessionManager.
     */
    void Done() override;

    // Process the connection's next packet.  "data" points just
    // beyond the IP header.  It's updated to point just beyond
    // the transport header (or whatever should be saved, if we
    // decide not to save the full packet contents).
    //
    // If record_packet is true, the packet should be recorded.
    // If record_content is true, then its entire contents should
    // be recorded, otherwise just up through the transport header.
    // Both are assumed set to true when called.
    void NextPacket(double t, bool is_orig, const IP_Hdr* ip, int len, int caplen, const u_char*& data,
                    int& record_packet, int& record_content,
                    // arguments for reproducing packets
                    const Packet* pkt);

    // Keys are only considered valid for a connection when a
    // connection is in the session map. If it is removed, the key
    // should be marked invalid.
    const detail::ConnKey& Key() const { return *key; }
    session::detail::Key SessionKey(bool copy) const override;

    const IPAddr& OrigAddr() const { return orig_addr; }
    const IPAddr& RespAddr() const { return resp_addr; }

    uint32_t OrigPort() const { return orig_port; }
    uint32_t RespPort() const { return resp_port; }

    void FlipRoles();

    analyzer::Analyzer* FindAnalyzer(analyzer::ID id);
    analyzer::Analyzer* FindAnalyzer(const zeek::Tag& tag); // find first in tree.
    analyzer::Analyzer* FindAnalyzer(const char* name);     // find first in tree.

    TransportProto ConnTransport() const { return proto; }
    std::string TransportIdentifier() const override {
        if ( proto == TRANSPORT_TCP )
            return "tcp";
        else if ( proto == TRANSPORT_UDP )
            return "udp";
        else if ( proto == TRANSPORT_ICMP )
            return "icmp";
        else
            return "unknown";
    }

    uint8_t KeyProto() const { return key->transport; }

    // Returns true if the packet reflects a reuse of this
    // connection (i.e., not a continuation but the beginning of
    // a new connection).
    bool IsReuse(double t, const u_char* pkt);

    /**
     * Returns the associated "connection" record.
     */
    const RecordValPtr& GetVal() override;

    void Match(detail::Rule::PatternType type, const u_char* data, int len, bool is_orig, bool bol, bool eol,
               bool clear_state);

    /**
     * Generates connection removal event(s).
     */
    void RemovalEvent() override;

    void Weird(const char* name, const char* addl = "", const char* source = "");
    bool DidWeird() const { return weird != 0; }

    inline bool FlagEvent(ConnEventToFlag e) {
        if ( e >= 0 && e < NUM_EVENTS_TO_FLAG ) {
            if ( suppress_event & (1 << e) )
                return false;
            suppress_event |= 1 << e;
        }

        return true;
    }

    void Describe(ODesc* d) const override;
    void IDString(ODesc* d) const;

    // Statistics.

    static uint64_t TotalConnections() { return total_connections; }
    static uint64_t CurrentConnections() { return current_connections; }

    // Sets the root of the analyzer tree as well as the primary PIA.
    void SetSessionAdapter(packet_analysis::IP::SessionAdapter* aa, analyzer::pia::PIA* pia);
    packet_analysis::IP::SessionAdapter* GetSessionAdapter() { return adapter; }
    analyzer::pia::PIA* GetPrimaryPIA() { return primary_PIA; }

    // Sets the transport protocol in use.
    void SetTransport(TransportProto arg_proto) { proto = arg_proto; }

    void SetUID(const UID& arg_uid) { uid = arg_uid; }

    UID GetUID() const { return uid; }

    std::shared_ptr<EncapsulationStack> GetEncapsulation() const { return encapsulation; }

    void CheckFlowLabel(bool is_orig, uint32_t flow_label);

    uint32_t GetOrigFlowLabel() { return orig_flow_label; }
    uint32_t GetRespFlowLabel() { return resp_flow_label; }

    bool PermitWeird(const char* name, uint64_t threshold, uint64_t rate, double duration);

    // Returns true once Done() is called.
    bool IsFinished() { return finished; }

private:
    friend class session::detail::Timer;

    IPAddr orig_addr;
    IPAddr resp_addr;
    uint32_t orig_port, resp_port; // in network order
    TransportProto proto;
    uint32_t orig_flow_label, resp_flow_label; // most recent IPv6 flow labels
    uint32_t vlan, inner_vlan;                 // VLAN this connection traverses, if available
    u_char orig_l2_addr[Packet::L2_ADDR_LEN];  // Link-layer originator address, if available
    u_char resp_l2_addr[Packet::L2_ADDR_LEN];  // Link-layer responder address, if available
    int suppress_event;                        // suppress certain events to once per conn.
    RecordValPtr conn_val;
    std::shared_ptr<EncapsulationStack> encapsulation; // tunnels
    uint8_t tunnel_changes = 0;

    detail::ConnKeyPtr key;

    unsigned int weird : 1;
    unsigned int finished : 1;
    unsigned int saw_first_orig_packet : 1, saw_first_resp_packet : 1;

    packet_analysis::IP::SessionAdapter* adapter;
    analyzer::pia::PIA* primary_PIA;

    UID uid; // Globally unique connection ID.
    detail::WeirdStateMap weird_state;

    // Count number of connections.
    static uint64_t total_connections;
    static uint64_t current_connections;
};

// The following is used by script optimization.
namespace detail {
extern RecordValPtr build_dummy_conn_record();
}

} // namespace zeek
