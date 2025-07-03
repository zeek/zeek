// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <netinet/in.h>

#include "zeek/Conn.h"
#include "zeek/ConnKey.h"
#include "zeek/IPAddr.h"
#include "zeek/net_util.h"

namespace zeek {

namespace detail {

/**
 * Struct for embedding into an IPBasedConnKey.
 */
struct PackedConnTuple {
    in6_addr ip1;
    in6_addr ip2;
    uint16_t port1 = 0;
    uint16_t port2 = 0;
    uint16_t proto = 0;
} __attribute__((packed, aligned));

} // namespace detail

/**
 * Abstract key class for IP-based connections.
 *
 * ConnKey instances for IP always hold a ConnTuple instance which is provided
 * by the IPBasedAnalyzer. The InitConnTuple() method stores a normalized version
 * in the tuple, losing the information about orig and responder.
 */
class IPBasedConnKey : public zeek::ConnKey {
public:
    /**
     * Initializes the key to the given 5-tuple. This canonicalizes the
     * packed tuple storage, including potential endpoint flips for
     * consistent connection lookups regardless of directionality.
     */
    void InitTuple(const IPAddr& src_addr, uint32_t src_port, const IPAddr& dst_addr, uint32_t dst_port, uint16_t proto,
                   bool is_one_way = false);

    /**
     * The source address the key got initialized with.
     */
    IPAddr SrcAddr() const { return flipped ? IPAddr(PackedTuple().ip2) : IPAddr(PackedTuple().ip1); }
    /**
     * The destination address the key got initialized with.
     */
    IPAddr DstAddr() const { return flipped ? IPAddr(PackedTuple().ip1) : IPAddr(PackedTuple().ip2); }
    /**
     * The source port the key got initialized with.
     */
    uint16_t SrcPort() const { return flipped ? PackedTuple().port2 : PackedTuple().port1; }
    /**
     * The destination port the key got initialized with.
     */
    uint16_t DstPort() const { return flipped ? PackedTuple().port1 : PackedTuple().port2; }
    /**
     * The IP protocol the key got initialized with.
     */
    uint16_t Proto() const { return PackedTuple().proto; }

    /**
     * @return The TransportProto value for this key's IP proto.
     */
    TransportProto GetTransportProto() const {
        switch ( Proto() ) {
            case IPPROTO_TCP: return TRANSPORT_TCP;
            case IPPROTO_UDP: return TRANSPORT_UDP;
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6: return TRANSPORT_ICMP;
            default: return TRANSPORT_UNKNOWN;
        }
    }

    /**
     * Flips the role of source and destination fields in the packed tuple.
     */
    void FlipRoles() { flipped = ! flipped; }

    /**
     * Flips the role of originator and responder.
     *
     * This overload will also flip fields of the conn_id and ctx record
     * values. The DoFlipRoles hook can be overridden to customize this process,
     * but that's usually not needed. The default implementation will flip
     * the orig_h/resp_h and orig_p/resp_p pairs.
     *
     * @param conn_id The conn_id record to populate.
     * @param ctx The conn_id's ctx record to populate.
     */
    void FlipRoles(RecordVal& conn_id, RecordVal& ctx) {
        FlipRoles();

        DoFlipRoles(conn_id, ctx);
    }

    /**
     * Return a modifiable reference to the embedded PackedConnTuple.
     *
     * This is virtual to give subclasses control over where
     * to place the tuple within the key.
     *
     * @return A modifiable reference to the embedded PackedConnTuple.
     */
    virtual detail::PackedConnTuple& PackedTuple() = 0;

    /**
     * Return a non-modifiable reference to the embedded PackedConnTuple.
     *
     * This is virtual to give subclasses control over where
     * to place the tuple within the key.
     *
     * @return A non-modifiable reference to the embedded PackedConnTuple.
     */
    virtual const detail::PackedConnTuple& PackedTuple() const = 0;

protected:
    /**
     * Overridden from ConnKey.
     *
     * This implementation sets orig_h, resp_h, orig_p, resp_p and proto
     * on the \a conn_id record value and leaves \a ctx untouched.
     *
     * When implementing subclasses of IPBasedConnKey, redef the script-layer
     * record type conn_id_ctx with the fields specific to your ConnKey implementation,
     * e.g. VLAN IDs. Then override this method to populate the fields of \a ctx based
     * on data stored in your custom ConnKey instance. Ensure to call
     * IPBasedConnKey::DoPopulateConnIdVal() to populate the common \a conn_id fields, too.
     *
     * @param conn_id The conn_id record to populate.
     * @param ctx The conn_id's ctx record to populate.
     */
    void DoPopulateConnIdVal(RecordVal& conn_id, RecordVal& ctx) override;

    /**
     * Hook for FlipRoles.
     *
     * The default implementation will flip the orig_h/resp_h and orig_p/resp_p pairs.
     *
     * @param conn_id The conn_id record to flip.
     * @param ctx The conn_id's ctx record to flip.
     */
    virtual void DoFlipRoles(RecordVal& conn_id, RecordVal& ctx);

    /**
     * Flag for tracking if src and dst addresses provided to InitTuple() were flipped.
     */
    bool flipped = false;
};

using IPBasedConnKeyPtr = std::unique_ptr<IPBasedConnKey>;

/**
 * The usual 5-tuple ConnKey, fully instantiable.
 */
class IPConnKey : public IPBasedConnKey {
public:
    /**
     * Constructor.
     *
     * Fill any holes in the key struct as we use the full tuple as a key.
     */
    IPConnKey() { memset(static_cast<void*>(&key), 0, sizeof(key)); }

    /**
     * @copydoc
     */
    detail::PackedConnTuple& PackedTuple() override { return key.tuple; }

    /**
     * @copydoc
     */
    const detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

protected:
    /**
     * @copydoc
     */
    zeek::session::detail::Key DoSessionKey() const override {
        return {reinterpret_cast<const void*>(&key), sizeof(key),
                // XXX: Not sure we need CONNECTION_KEY_TYPE?
                session::detail::Key::CONNECTION_KEY_TYPE};
    }

private:
    struct {
        struct detail::PackedConnTuple tuple;
    } key;
};

} // namespace zeek
