// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <netinet/in.h>
#include <optional>

#include "zeek/Conn.h"
#include "zeek/ConnKey.h"

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
    uint16_t proto = detail::INVALID_CONN_KEY_IP_PROTO;
} __attribute__((packed, aligned));

} // namespace detail

/**
 * Abstract key class for IP-based connections.
 *
 * ConnKey instances for IP always hold a ConnTuple instance which is provided
 * by the IPBasedAnalyzer. The InitConnTuple() method stored a normalized version
 * in the tuple, loosing the information about orig and responder.
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

    std::optional<std::string> Error() const override;

    /**
     * Return a modifiable reference to the embedded PackedConnTuple.
     *
     * This is virtual to give subclasses control over where
     * to place the tuple within the key.
     */
    virtual detail::PackedConnTuple& PackedTuple() const = 0;

protected:
    bool flipped = false;
};

using IPBasedConnKeyPtr = std::unique_ptr<IPBasedConnKey>;

/**
 * The usual 5-tuple ConnKey, fully instantiable.
 */
class IPConnKey : public IPBasedConnKey {
public:
    IPConnKey() {
        // Fill any holes since we use the full tuple as a key:
        memset(static_cast<void*>(&key), '\0', sizeof(key));
    }

    zeek::session::detail::Key SessionKey() const override {
        return zeek::session::detail::Key(reinterpret_cast<const void*>(&key), sizeof(key),
                                          // XXX: Not sure we need CONNECTION_KEY_TYPE?
                                          session::detail::Key::CONNECTION_KEY_TYPE);
    }

    detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

private:
    struct {
        // mutable to allow PackedTuple() to remain const.
        mutable struct detail::PackedConnTuple tuple;
    } key;
};

} // namespace zeek
