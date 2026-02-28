// See the file "COPYING" in the main distribution directory for copyright.

// Functionality to support &publish_on_change on tables and sets.

#pragma once

#include <cstdint>
#include <memory>

#include "zeek/IntrusivePtr.h"

namespace zeek {

class RecordVal;
class VectorVal;
using VectorValPtr = IntrusivePtr<VectorVal>;

namespace detail {

enum class TableChange : uint8_t {
    New = 1,
    Updated = 1 << 1,
    Deleted = 1 << 2,
    Expired = 1 << 3,
};

class PublishOnChangeState {
public:
    /**
     * Parse the record given to &publish_on_change and create a fresh
     * PublishOnChangeState instance from it.
     *
     * @param rec The input record.
     *
     * @return PublishOnChangeState
     */
    static std::unique_ptr<PublishOnChangeState> FromRecord(const zeek::RecordVal& rec);

    PublishOnChangeState(uint8_t changes_mask, size_t max_batch_size, double max_batch_delay);


private:
    uint8_t changes_mask = 0;     // Bitmask created from $changes field.
    double max_batch_delay = 0.0; // Maximum delay before publishing the batch
    int max_batch_size = 0;       // Maximum size of queued_changes.

    double last_publish_ts = 0.0; //

    zeek::VectorValPtr queued_changes;
};

} // namespace detail
} // namespace zeek
