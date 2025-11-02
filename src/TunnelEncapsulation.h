// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>

#include "zeek/IP.h"
#include "zeek/IPAddr.h"
#include "zeek/NetVar.h"
#include "zeek/UID.h"

namespace zeek {

class Connection;

/**
 * Represents various types of tunnel "connections", that is, a pair of
 * endpoints whose communication encapsulates inner IP packets.  This could
 * mean IP packets nested inside IP packets or IP packets nested inside a
 * transport layer protocol.  EncapsulatingConn's are assigned a UID, which can
 * be shared with Connection's in the case the tunnel uses a transport-layer.
 */
class EncapsulatingConn {
public:
    /**
     * Default tunnel connection constructor.
     */
    EncapsulatingConn() = default;

    /**
     * Construct an IP tunnel "connection" with its own UID.
     * The assignment of "source" and "destination" addresses here can be
     * arbitrary, comparison between EncapsulatingConn objects will treat IP
     * tunnels as equivalent as long as the same two endpoints are involved.
     *
     * @param s The tunnel source address, likely taken from an IP header.
     * @param d The tunnel destination address, likely taken from an IP header.
     * @param t The type of IP tunnel.
     */
    EncapsulatingConn(const IPAddr& s, const IPAddr& d, BifEnum::Tunnel::Type t = BifEnum::Tunnel::IP,
                      uint16_t ip_proto = UNKNOWN_IP_PROTO)
        : src_addr(s), dst_addr(d), ip_proto(ip_proto), type(t), uid(UID(detail::bits_per_uid)) {
        switch ( ip_proto ) {
            case IPPROTO_ICMP: proto = TRANSPORT_ICMP; break;
            case IPPROTO_UDP: proto = TRANSPORT_UDP; break;
            case IPPROTO_TCP: proto = TRANSPORT_TCP; break;
            default: proto = TRANSPORT_UNKNOWN; break;
        }
    }

    /**
     * Construct a tunnel connection using information from an already existing
     * transport-layer-aware connection object.
     *
     * @param c The connection from which endpoint information can be extracted.
     *        If it already has a UID associated with it, that gets inherited,
     *        otherwise a new UID is created for this tunnel and \a c.
     * @param t The type of tunneling that is occurring over the connection.
     */
    EncapsulatingConn(Connection* c, BifEnum::Tunnel::Type t);

    /**
     * Copy constructor.
     */
    EncapsulatingConn(const EncapsulatingConn& other) = default;

    /**
     * Destructor.
     */
    ~EncapsulatingConn() {}

    EncapsulatingConn& operator=(const EncapsulatingConn& other) = default;

    BifEnum::Tunnel::Type Type() const { return type; }

    /**
     * Returns record value of type "EncapsulatingConn" representing the tunnel.
     */
    RecordValPtr ToVal() const;

    friend bool operator==(const EncapsulatingConn& ec1, const EncapsulatingConn& ec2) {
        if ( ec1.type != ec2.type )
            return false;

        if ( ec1.type == BifEnum::Tunnel::IP || ec1.type == BifEnum::Tunnel::GRE )
            // Reversing endpoints is still same tunnel.
            return ec1.uid == ec2.uid && ec1.proto == ec2.proto && ec1.ip_proto == ec2.ip_proto &&
                   ((ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr) ||
                    (ec1.src_addr == ec2.dst_addr && ec1.dst_addr == ec2.src_addr));

        if ( ec1.type == BifEnum::Tunnel::VXLAN )
            // Reversing endpoints is still same tunnel, destination port is
            // always the same.
            return ec1.dst_port == ec2.dst_port && ec1.uid == ec2.uid && ec1.proto == ec2.proto &&
                   ec1.ip_proto == ec2.ip_proto &&
                   ((ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr) ||
                    (ec1.src_addr == ec2.dst_addr && ec1.dst_addr == ec2.src_addr));

        return ec1.src_addr == ec2.src_addr && ec1.dst_addr == ec2.dst_addr && ec1.src_port == ec2.src_port &&
               ec1.dst_port == ec2.dst_port && ec1.uid == ec2.uid && ec1.proto == ec2.proto &&
               ec1.ip_proto == ec2.ip_proto;
    }

    friend bool operator!=(const EncapsulatingConn& ec1, const EncapsulatingConn& ec2) { return ! (ec1 == ec2); }

    // TODO: temporarily public
    std::shared_ptr<IP_Hdr> ip_hdr;

protected:
    IPAddr src_addr;
    IPAddr dst_addr;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    TransportProto proto = TRANSPORT_UNKNOWN;
    uint16_t ip_proto = UNKNOWN_IP_PROTO;
    BifEnum::Tunnel::Type type = BifEnum::Tunnel::NONE;
    UID uid;
};

/**
 * Abstracts an arbitrary amount of nested tunneling.
 */
class EncapsulationStack {
public:
    EncapsulationStack() = default;

    EncapsulationStack(const EncapsulationStack& other) {
        if ( other.conns )
            conns = new std::vector<EncapsulatingConn>(*(other.conns));
        else
            conns = nullptr;
    }

    EncapsulationStack& operator=(const EncapsulationStack& other) {
        if ( this == &other )
            return *this;

        delete conns;

        if ( other.conns )
            conns = new std::vector<EncapsulatingConn>(*(other.conns));
        else
            conns = nullptr;

        return *this;
    }

    ~EncapsulationStack() { delete conns; }

    /**
     * Add a new inner-most tunnel to the EncapsulationStack.
     *
     * @param c The new inner-most tunnel to append to the tunnel chain.
     */
    void Add(const EncapsulatingConn& c) {
        if ( ! conns )
            conns = new std::vector<EncapsulatingConn>();

        conns->push_back(c);
    }

    /**
     * Return how many nested tunnels are involved in a encapsulation, zero
     * meaning no tunnels are present.
     */
    size_t Depth() const { return conns ? conns->size() : 0; }

    /**
     * Return the tunnel type of the inner-most tunnel.
     */
    BifEnum::Tunnel::Type LastType() const {
        return conns ? (*conns)[conns->size() - 1].Type() : BifEnum::Tunnel::NONE;
    }

    /**
     * Get the value of type "EncapsulatingConnVector" represented by the
     * entire encapsulation chain.
     */
    VectorValPtr ToVal() const {
        auto vv = make_intrusive<VectorVal>(id::find_type<VectorType>("EncapsulatingConnVector"));

        if ( conns ) {
            for ( size_t i = 0; i < conns->size(); ++i )
                vv->Assign(i, (*conns)[i].ToVal());
        }

        return vv;
    }

    friend bool operator==(const EncapsulationStack& e1, const EncapsulationStack& e2);

    friend bool operator!=(const EncapsulationStack& e1, const EncapsulationStack& e2) { return ! (e1 == e2); }

    /**
     * Returns a pointer the last element in the stack. Returns a nullptr
     * if the stack is empty or hasn't been initialized yet.
     */
    EncapsulatingConn* Last() { return Depth() > 0 ? &(conns->back()) : nullptr; }

    /**
     * Returns an EncapsulatingConn from the requested index in the stack.
     *
     * @param index An index to look up. Note this is one-indexed, since it's generally
     * looked up using a value from Depth().
     * @return The corresponding EncapsulatingConn, or a nullptr if the requested index is
     * out of range.
     */
    EncapsulatingConn* At(size_t index) {
        if ( index > 0 && index <= Depth() )
            return &(conns->at(index - 1));

        return nullptr;
    }

    /**
     * Pops the last element off the encapsulation stack.
     */
    void Pop();

protected:
    std::vector<EncapsulatingConn>* conns = nullptr;
};

} // namespace zeek
