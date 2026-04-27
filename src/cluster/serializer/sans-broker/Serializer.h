// See the file "COPYING" in the main distribution directory for copyright.
//
#include <zeek/IntrusivePtr.h>
#include <cstdint>
#include <iterator>
#include <span>
#include <vector>

#include "zeek/cluster/Serializer.h"

// A Val-based re-implementation of the Broker binary V1 format without going through
// the intermediate broker::data types.
namespace zeek {

class Val;
class Type;
using ValPtr = IntrusivePtr<Val>;
using TypePtr = IntrusivePtr<Type>;

using byte_buffer = std::vector<std::byte>;
using byte_buffer_span = std::span<const std::byte>;

namespace cluster {

namespace format::broker::bin::v1 {

/// A tag that discriminates the type of a @ref data or @ref variant object.
enum class variant_tag : uint8_t {
    // Warning: the values *must* have the same order as `data_variant`, because
    // the integer value for this tag must be equal to `get_data().index()`.
    none,
    boolean,
    count,
    integer,
    real,
    string,     // 5
    address,    // 6
    subnet,     // 7
    port,       // 8
    timestamp,  // 9
    timespan,   // 10
    enum_value, // 11
    set,
    table,
    list,          // 14
    vector = list, // alias for backward compatibility
};

// An Event is a Message with Type=1
// ProtocolVersion, Type, Content
//
// Content is another list
// Name (string), Args (vector), Metadata (vector)
//
template<typename It>
concept byte_output_iterator = std::output_iterator<It, std::byte>;


bool encode(const zeek::Val& val, std::back_insert_iterator<zeek::byte_buffer> out);

/**
 * Decode a Val of type type from span s, moving s forward by the consumed bytes.
 */
ValPtr decode(zeek::byte_buffer_span& s, const zeek::TypePtr& type);


} // namespace format::broker::bin::v1

namespace detail {

/**
 * Event serializer re-implementing the broker bin v1 format.
 */
class SansBrokerBinV1_Serializer : public EventSerializer {
public:
    SansBrokerBinV1_Serializer() : EventSerializer("broker-bin-v1") {}

    ~SansBrokerBinV1_Serializer() = default;

    bool SerializeEvent(byte_buffer& buf, const cluster::Event& event) override;

    std::optional<cluster::Event> UnserializeEvent(byte_buffer_span buf) override;
};

} // namespace detail

} // namespace cluster
} // namespace zeek
