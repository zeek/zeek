// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/UID.h"

#include <cstdlib>

#include "zeek/Reporter.h"
#include "zeek/util.h"

namespace zeek {

void UID::Set(zeek_uint_t bits, const uint64_t* v, size_t n) {
    initialized = true;

    memset(uid, 0, sizeof(uid));

    if ( bits > UID_LEN * 64 )
        bits = UID_LEN * 64;

    div_t res = div(bits, 64);
    size_t size = res.rem ? res.quot + 1 : res.quot;

    for ( size_t i = 0; i < size; ++i )
        uid[i] = v && i < n ? v[i] : util::calculate_unique_id();

    if ( res.rem )
        uid[0] >>= 64 - res.rem;
}

std::string UID::Base62(std::string prefix) const {
    if ( ! initialized )
        reporter->InternalError("use of uninitialized UID");

    char tmp[sizeof(uid) * 8 + 1]; // enough for even binary representation
    for ( const auto& digit : uid )
        prefix.append(util::uitoa_n(digit, tmp, sizeof(tmp), 62));

    return prefix;
}

} // namespace zeek
