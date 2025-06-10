// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <optional>

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
    virtual ~ConnKey() {}

    /**
     * Initialization of this key with the current packet.
     */
    void Init(const Packet& pkt) { DoInit(pkt); }

    /**
     * When Zeek renders a connection into a script-layer record, it calls this
     * method to provide custom conn_id fields unique to this ConnKey, such as
     * VLAN fields. This only needs to fill in fields in addition to Zeek's
     * five-tuple (i.e., complete the record, not fill all of it -- hence the
     * name).
     *
     * The default implementation does nothing.
     */
    virtual void CompleteConnIdVal(RecordValPtr& conn_id) {};

    /**
     * Return a non-owning session::detail::Key instance for connection lookups.
     *
     * Callers that need more than a View should copy the data. Callers are not
     * supposed to hold on to the Key for longer than the ConnKey instance
     * exists. Think string_view or span!
     *
     * @return A zeek::session::detail::Key
     */
    virtual zeek::session::detail::Key SessionKey() const = 0;

    /**
     * Get the error state of a ConnKey, if any.
     *
     * Instances of a ConnKey created from zeek::Val instances via
     * Builder::FromVal() may not be valid. Calling Error() can be used to
     * gather a description of the encountered error.
     */
    virtual std::optional<std::string> Error() const = 0;

protected:
    /**
     * Hook method for custom initialization.
     *
     * This may also take information from the global context rather than just
     * the packet.
     *
     * @param p The current packet
     */
    virtual void DoInit(const Packet& pkt) {};
};

using ConnKeyPtr = std::unique_ptr<ConnKey>;

} // namespace zeek
