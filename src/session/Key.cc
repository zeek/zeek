// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/session/Key.h"

#include <cstring>

namespace zeek::session::detail {

Key::Key(const void* session, size_t size, size_t type, bool copy, bool adopt) : size(size), type(type) {
    data = reinterpret_cast<const uint8_t*>(session);

    if ( copy )
        CopyData();

    owns_data = copy || adopt;
}

Key::Key(Key&& rhs) noexcept {
    data = rhs.data;
    size = rhs.size;
    type = rhs.type;
    owns_data = rhs.owns_data;

    rhs.data = nullptr;
    rhs.size = 0;
    rhs.owns_data = false;
}

Key& Key::operator=(Key&& rhs) noexcept {
    if ( this != &rhs ) {
        data = rhs.data;
        size = rhs.size;
        type = rhs.type;
        owns_data = rhs.owns_data;

        rhs.data = nullptr;
        rhs.size = 0;
        rhs.owns_data = false;
    }

    return *this;
}

Key::~Key() {
    if ( owns_data )
        delete[] data;
}

void Key::CopyData() {
    if ( owns_data )
        return;

    owns_data = true;

    uint8_t* temp = new uint8_t[size];
    memcpy(temp, data, size);
    data = temp;
}

bool Key::operator<(const Key& rhs) const {
    if ( size != rhs.size )
        return size < rhs.size;
    else if ( type != rhs.type )
        return type < rhs.type;

    return memcmp(data, rhs.data, size) < 0;
}

bool Key::operator==(const Key& rhs) const {
    if ( size != rhs.size || type != rhs.type )
        return false;

    return memcmp(data, rhs.data, size) == 0;
}

} // namespace zeek::session::detail
