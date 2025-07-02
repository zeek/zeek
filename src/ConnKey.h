// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/IntrusivePtr.h"
#include "zeek/session/Key.h"

namespace zeek {

class Packet;

class RecordVal;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;

/**
 * Abstract ConnKey, for any type of connection.
 */
class ConnKey {
public:
    virtual ~ConnKey() = default;

    /**
     * Initialization of this key with the current packet.
     *
     * @param pkt The packet that's currently being processed.
     */
    void Init(const Packet& pkt) { DoInit(pkt); }

    /**
     * When Zeek renders a connection into a script-layer record, it calls this
     * method to populate custom conn_id fields unique to this ConnKey, such as
     * VLAN fields. This only needs to populate in fields in addition to Zeek's
     * five-tuple (i.e., complete the record, not populate all of it).
     *
     * The default implementation does nothing.
     *
     * @param conn_id The conn_id record to populate.
     */
    void PopulateConnIdVal(RecordVal& conn_id) { DoPopulateConnIdVal(conn_id); };

    /**
     * Return a non-owning session::detail::Key instance for connection lookups.
     *
     * Callers that need more than just a view of the key should copy the data.
     * Callers are not supposed to hold on to the returned Key for longer than
     * the ConnKey instance exists.
     *
     * @return A zeek::session::detail::Key
     */
    zeek::session::detail::Key SessionKey() const { return DoSessionKey(); }

protected:
    /**
     * Hook method for ConnKey::Init.
     *
     * Note that a given ConnKey instance may be re-used for different
     * packets if it wasn't consumed to create a new connection. Therefore,
     * implementers of this method are required to always set all fields
     * that will affect the SessionKey result within DoInit anew.
     *
     * This a bit of an optimization done in the packet path that's shining
     * through here. Rather than introducing a dedicated Reset method,
     * implementers are asked to reset the key at initialization time
     * which they most likely would do anyhow.
     *
     * @param pkt The packet that's currently being processed.
     */
    virtual void DoInit(const Packet& pkt){};

    /**
     * Hook method for ConnKey::PopulateConnIdVal.
     *
     * The default implementation does nothing.
     */
    virtual void DoPopulateConnIdVal(RecordVal& conn_id) {}

    /**
     * Hook method for implementing ConnKey::SessionKey.
     *
     * @return A zeek::session::detail::Key
     */
    virtual session::detail::Key DoSessionKey() const = 0;
};

using ConnKeyPtr = std::unique_ptr<ConnKey>;

} // namespace zeek
