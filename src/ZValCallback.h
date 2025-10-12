// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/ZVal.h"

namespace zeek::detail {

/**
 * The ZValCallback class provides a mechanism to lazily evaluate record fields.
 *
 * The first use-case of this is to query the endpoint's fields that represent
 * the current state of a connection (size, num_pkts, num_bytes_ip, ...) and also
 * a connection's duration and history field from the underlying connection. These
 * are so called volatile record fields.
 *
 * A raw pointer to a ZValCallback can be stored in a ZValElement within a RecordVal.
 * The ZValElement's holds_callback flag is set to true for such fields.
 * The non-optimized RecordVal::GetField(...) will check this flag and call
 * the ZValCallback pointed at to produce a ZVal to use in the script layer.
 *
 * The callback takes two ZVal references. While currently the interface is
 * only used for deferred evaluation of record fields, it could be placed on
 * tables or even vectors in which case the ``obj`` and ``k`` parameters would
 * be a table and its key, while for records, it's the record and ``k`` is the
 * field offset.
 *
 * Lifetime Management:
 *
 * The callback isn't owned by the RecordVal or ZValElement. Instead, the idea is that
 * the owner is external to the RecordVal and managed separately. For example, the Conn
 * object for a given connection RecordVal is the owner of the callback instances. The
 * owner explicitly needs to clear the callback pointers stored in the ZValElement when
 * the RecordVal outlives the owner. In the Conn class this happens during Done(). In fact,
 * the callback owner can replace the field which stores the callback with a concrete
 * ZValElement instance representing the most recent value produced by the callback.
 */
class ZValCallback {
public:
    virtual ~ZValCallback() = default;

    /**
     * Called for accessing a field via RecordVal::GetField().
     *
     * To determine the type of the requested field, go via v.GetType<RecordType>()->FieldDecl(field).
     *
     * @param v The RecordVal instance for which the callback is invoked.
     * @param k The key/field index for which the callback was invoked. For records, the ZVal is a count.
     *
     * @return Implementations are required to return a ZVal instance that matches the expected type.
     */
    virtual ZVal operator()(const ZVal& obj, const ZVal& k) const = 0;

    // Food for thought: How about setter support? This could allow calling
    // the following operator for assignments to a record field.
    //
    // virtual void operator()(RecordVal *v, int field, ZVal zval)
};

} // namespace zeek::detail
