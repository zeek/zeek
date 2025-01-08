// See the file "COPYING" in the main distribution directory for copyright.

#include <hilti/rt/libhilti.h>

namespace hlt_websocket::WebSocket {

// // Implement XOR unmasking of WebSocket frames in C++ since this code is very hot.
//
// https://github.com/zeek/spicy/issues/1663
::hilti::rt::Bytes fast_unmask(const hilti::rt::integer::safe<uint64_t>& masking_key_idx,
                               const hilti::rt::Vector<hilti::rt::integer::safe<uint8_t>>& masking_key,
                               const hilti::rt::Bytes& chunk) {
    constexpr size_t masking_key_size = 4;

    if ( masking_key.size() != masking_key_size )
        throw hilti::rt::UsageError(hilti::rt::fmt("wrong masking_key size %ld", masking_key.size()));

    const uint64_t mi = masking_key_idx;
    std::array<uint8_t, masking_key_size> unsafe_masking_key;

    size_t i = 0;
    for ( auto it = masking_key.unsafeBegin(); it != masking_key.unsafeEnd(); ++it )
        unsafe_masking_key[i++] = *it;

    std::string unmasked(chunk.size(), '\0');
    const auto& chunk_str = chunk.str();

    for ( size_t i = 0; i < chunk_str.size(); i++ )
        unmasked[i] = chunk_str[i] ^ unsafe_masking_key[(mi + i) % unsafe_masking_key.size()];

    return {std::move(unmasked)};
}

} // namespace hlt_websocket::WebSocket
