// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/ZVal.h"

namespace zeek {

class RecordVal;

namespace detail {

/**
 * The RecordFieldCallback class provides a mechanism to lazily evaluate
 * record fields.
 *
 * The first use-case of this functionality is to query the endpoint's fields that
 * represent the current state of a connection (size, num_pkts, num_bytes_ip, ...)
 * and also a connection's duration and history fields. Record fields backed by
 * a callback are also called volatile record fields - the core may update these
 * based on packet data.
 *
 * The ZValElement vector in a record can store a raw pointer to a RecordFieldCallback
 * instance. The ZValElement's state is set to "field callback" for such fields.
 * RecordVal::GetField(...) will check for this state and invoke the callback
 * to produce a ZVal that can be used in the script layer or elsewhere.
 *
 * Lifetime Management:
 *
 * The callback instance isn't owned by the RecordVal or ZValElement. Instead, the idea is
 * that the owner is external to the RecordVal and managed separately. For example, the Conn
 * object for a given connection's RecordVal is the owner of the callback instances. The
 * owner explicitly needs to clear the callback pointers stored in record's ZValElement
 * array when a RecordVal outlives the callback instance. In the Conn class this happens
 * during Done(). In fact, the callback owner replaces the fields which store the callbacks
 * with a ZValElement holding a ZVal representing the most recent value that the
 * callback would have produced.
 */
class RecordFieldCallback {
public:
    virtual ~RecordFieldCallback() = default;

    /**
     * Called for accessing a field via RecordVal::GetField().
     *
     * To determine the type of the requested field, gather it via
     * r.GetType<RecordType>()->FieldDecl(field).
     *
     * @param rv The RecordVal instance for which the callback is invoked. The value should not be modified.
     * @param field The field index for which the callback is invoked.
     *
     * @return Implementations are required to return a ZVal instance that matches the expected type. The caller owns
     * the returned reference if this is a managed ZVal.
     *
     */
    virtual ZVal Invoke(const RecordVal& rv, int field) const = 0;

    // Food for thought: How about setter support? This could allow calling
    // the following operator for assignments to a record field to change
    // something directly in the core.
    //
    // virtual void Invoke()(RecordVal &rv, int field, ZVal zval)
};

} // namespace detail
} // namespace zeek
