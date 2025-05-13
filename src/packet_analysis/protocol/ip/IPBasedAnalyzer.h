// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <netinet/in.h>
#include <map>
#include <optional>
#include <set>

#include "zeek/Conn.h"
#include "zeek/Tag.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek {
class Connection;

/**
 * IP specific ConnTuple.
 */
struct ConnTuple {
    IPAddr src_addr;
    IPAddr dst_addr;
    uint32_t src_port = 0;
    uint32_t dst_port = 0;
    uint16_t proto = UNKNOWN_IP_PROTO;
    bool is_one_way = false; // Can we ditch this fro from here?
};

namespace detail {

// UNKNOWN_IP_PROTO is 65535
constexpr uint16_t INVALID_CONN_KEY_IP_PROTO = 65534;

/**
 * Struct for embedding into a IPBasedConnKey.
 */
struct RawConnTuple {
    in6_addr ip1;
    in6_addr ip2;
    uint16_t port1 = 0;
    uint16_t port2 = 0;
    uint16_t transport = detail::INVALID_CONN_KEY_IP_PROTO;
} __attribute__((packed, aligned));

/**
 * Initialize a raw conn tuple from a conn tuple in canonicalized form.
 */
inline void init_raw_tuple(RawConnTuple& t, const ConnTuple& ct) {
    if ( ct.is_one_way || addr_port_canon_lt(ct.src_addr, ct.src_port, ct.dst_addr, ct.dst_port) ) {
        ct.src_addr.CopyIPv6(&t.ip1);
        ct.dst_addr.CopyIPv6(&t.ip2);
        t.port1 = ct.src_port;
        t.port2 = ct.dst_port;
    }
    else {
        ct.dst_addr.CopyIPv6(&t.ip1);
        ct.src_addr.CopyIPv6(&t.ip2);
        t.port1 = ct.dst_port;
        t.port2 = ct.src_port;
    }

    t.transport = ct.proto;
}

} // namespace detail

/**
 * Abstract key class for IP based connections.
 *
 * ConnKey instances for IP always hold a ConnTuple instance which is provided
 * by the IPBasedAnalyzer. The InitConnTuple() method stored a normalized version
 * in the tuple, loosing the information about orig and responder.
 */
class IPBasedConnKey : public zeek::ConnKey {
public:
    /**
     * Initialization function.
     *
     * ConnKey::Init() will invoke ConnKey::DoInit(), allowing
     * subclasses to hook into the initialization of the key.
     */
    void Init(const ConnTuple& ct, const Packet& pkt) {
        init_raw_tuple(RawTuple(), ct);
        ConnKey::Init(pkt);
    }

    std::optional<std::string> Error() const override {
        auto& rt = RawTuple();
        if ( rt.transport == detail::INVALID_CONN_KEY_IP_PROTO )
            return "invalid connection ID record";
        if ( rt.transport == UNKNOWN_IP_PROTO )
            return "invalid connection ID record: the proto field has the \"unknown\" 65535 value. Did you forget to "
                   "set it?";

        return std::nullopt;
    }

    /**
     * Return a modifiable version of the embedded RawConnTuple.
     *
     * This is virtual such that subclasses can control where
     * they'd like to place the RawConnTuple within the key.
     */
    virtual detail::RawConnTuple& RawTuple() const = 0;
};

using IPBasedConnKeyPtr = std::unique_ptr<IPBasedConnKey>;


/**
 * A usual 5 tuple conn key.
 */
class IPConnKey : public IPBasedConnKey {
public:
    IPConnKey() {
        // Fill holes as we use the full tuple as a Key!
        memset(static_cast<void*>(&key), '\0', sizeof(key));
    }

    zeek::Span<const std::byte> Key() const override {
        return {reinterpret_cast<const std::byte*>(&key), reinterpret_cast<const std::byte*>(&key) + sizeof(key)};
    }

    detail::RawConnTuple& RawTuple() const override { return key.tuple; }

private:
    struct {
        // mutable for non-const RawTuple() return value.
        mutable struct detail::RawConnTuple tuple;
    } key;
};

} // namespace zeek

namespace zeek::analyzer::pia {
class PIA;
}

namespace zeek::packet_analysis::IP {

class SessionAdapter;

/**
 * A base class for reuse by packet analyzers based on IP. This is used by default
 * by the TCP, UDP, and ICMP analyzers to reduce a large amount of duplicated code
 * that those plugins have in common.
 */
class IPBasedAnalyzer : public Analyzer {
public:
    ~IPBasedAnalyzer() override;

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    /**
     * Returns true if the analyzer determines that in fact a new
     * connection has started without the connection statement having
     * terminated the previous one, i.e., the new data is arriving at
     * what's the analyzer for the previous instance. This is used only
     * for TCP.
     */
    virtual bool IsReuse(double t, const u_char* pkt) { return false; }

    /**
     * Registers a well-known port for an analyzer. Once registered,
     * connection on that port will start with a corresponding analyzer
     * assigned.
     *
     * @param tag The analyzer's tag.
     * @param port The port's number.
     * @return True if successful.
     */
    bool RegisterAnalyzerForPort(const zeek::Tag& tag, uint32_t port);

    /**
     * Unregisters a well-known port for an analyzer.
     *
     * @param tag The analyzer's tag.
     * @param port The port's number.
     * @param tag The analyzer's tag as an enum of script type \c
     * Tag.
     */
    bool UnregisterAnalyzerForPort(const zeek::Tag& tag, uint32_t port);

    /**
     * Dumps information about the registered session analyzers per port.
     * Used by analyzer::Manager.
     */
    void DumpPortDebug();

    /**
     * Updates the internal pointer to the script-level variable `ignore_checksums_nets`.
     * This is used to prevent repeated (costly) lookup of the script-level variable
     * by IP-based analyzers.
     *
     * @param t New value of ignore_checksums_nets
     */
    static void SetIgnoreChecksumsNets(TableValPtr t);

    /**
     * Gets the internal pointer to the script-level variable `ignore_checksums_nets`.
     * This is used to prevent repeated (costly) lookup of the script-level variable
     * by IP-based analyzers.
     *
     * @return Current value of `ignore_checksums_nets`.
     */
    static TableValPtr GetIgnoreChecksumsNets();

protected:
    /**
     * Construct a new IP-based analyzer.
     *
     * @param name The name for the type of analyzer. The name must match
     * the one the corresponding Component registers.
     * @param proto The transport protocol implemented by this analyzer.
     * @param mask The mask used to determine if a port is a server port
     * for this protocol. This is used by IsLikelyServerPort().
     * @param report_unknown_protocols Flag for whether to report unknown
     * protocols during packet forwarding. This is typically false for IP
     * protocols since packets may go into the session analysis framework
     * as well.
     */
    IPBasedAnalyzer(const char* name, TransportProto proto, uint32_t mask, bool report_unknown_protocols);

    /**
     * Parse the header from the packet into a ConnTuple object.
     */
    virtual bool BuildConnTuple(size_t len, const uint8_t* data, Packet* packet, ConnTuple& tuple) = 0;

    /**
     * Continues process of packet after the connection has been inserted into the
     * session manager. This should be implemented by all child classes.
     *
     * @param conn The connection currently being processed.
     * @param t The timestamp for the current packet.
     * @param is_orig Flag denoting whether this packet is from the originator of
     * the connection.
     * @param remaining The remaining about of data in the packet.
     * @param pkt The packet being processed.
     */
    virtual void DeliverPacket(Connection* conn, double t, bool is_orig, int remaining, Packet* pkt) {}

    /**
     * Upon seeing the first packet of a connection, checks whether we want
     * to analyze it (e.g. we may not want to look at partial connections)
     * and, if yes, whether we should flip the roles of originator and
     * responder based on known ports and such.
     *
     * @param src_port The source port of the connection.
     * @param dst_port The destination port of the connection.
     * @param data The payload data for the packet being processed.
     * @param flip_roles Return value if the roles should be flipped.
     * @return True if the connection is wanted. False otherwise.
     */
    virtual bool WantConnection(uint16_t src_port, uint16_t dst_port, const u_char* data, bool& flip_roles) const {
        flip_roles = false;
        return true;
    }

    /**
     * Returns an analyzer adapter appropriate for this IP-based analyzer. This adapter
     * is used to hook into the session analyzer framework. This function can also be used
     * to do any extra initialization of connection timers, etc.
     */
    virtual SessionAdapter* MakeSessionAdapter(Connection* conn) = 0;

    /**
     * Returns a PIA appropriate for this IP-based analyzer. This method is optional to
     * override in child classes, as not all analyzers need a PIA.
     */
    virtual analyzer::pia::PIA* MakePIA(Connection* conn) { return nullptr; }

    /**
     * Verifies that there is enough data in the packet to process the header
     * length requested.
     *
     * @param min_hdr_len The minimum data in bytes that needs to exist.
     * @param remaining The remaining number of bytes in the packet reported by
     * previous analyzer.
     * @param packet The packet being processed. This will be used to pull out the
     * number of bytes the IP header says we have remaining.
     */
    bool CheckHeaderTrunc(size_t min_hdr_len, size_t remaining, Packet* packet);

    /**
     * Returns true if the port corresponds to an application for which there
     * is a Zeek analyzer (even if it might not be used by the present policy
     * script) or if it's generally a likely server port.
     *
     * @param port The port number to check, in host order.
     */
    bool IsLikelyServerPort(uint32_t port) const;

private:
    // While this is storing session analyzer tags, we store it here since packet analyzers
    // are persistent objects. We can't do this in the adapters because those get created
    // and destroyed for each connection.
    using tag_set = std::set<zeek::Tag>;
    using analyzer_map_by_port = std::map<uint32_t, tag_set*>;
    analyzer_map_by_port analyzers_by_port;

    tag_set* LookupPort(uint32_t port, bool add_if_not_found);

    /**
     * Creates a new Connection object from data gleaned from the current packet.
     *
     * @param id A connection ID generated from the packet data. This should have been
     * passed in from a child analyzer.
     * @param key A connection ID key generated from the ID.
     * @param pkt The packet associated with the new connection.
     */
    zeek::Connection* NewConn(IPBasedConnKeyPtr key, ConnTuple& ct, const Packet* pkt);

    void BuildSessionAnalyzerTree(Connection* conn);

    TransportProto transport;
    uint32_t server_port_mask;
    static TableValPtr ignore_checksums_nets_table;
};

} // namespace zeek::packet_analysis::IP
