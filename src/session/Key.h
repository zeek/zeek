// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <cstdint>

#include "zeek/Hash.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Span.h"

namespace zeek::session::detail {

struct KeyHash;

/**
 * This type is used as the key for the map in SessionManager. It represents a
 * raw block of memory that points to a key of some type for a session, such as
 * a ConnKey for a Connection. This allows us to do type-independent
 * comparison of the keys in the map. By default, this type does not maintain
 * the lifetime of the data pointed to by the Key. It only holds a
 * pointer. When a Key object is inserted into the SessionManager's map,
 * the data is copied into the object so the lifetime of the key data is
 * guaranteed over the lifetime of the map entry.
 */
class Key final {
public:
    const static size_t CONNECTION_KEY_TYPE = 0;

    /**
     * Create a new session key from a data pointer.
     *
     * @param session A pointer to the data for the key.
     * @param size The size of the key data, in bytes.
     * @param type An identifier for the type of this key. The value used should be
     * unique across all types of session keys. CONNECTION_KEY_TYPE (0) is used by
     * Connection sessions and is reserved. This value is used to avoid collisions
     * when doing comparisons of the memory stored by keys.
     * @param copy Flag for whether the data should be copied into the Key
     * during construction. This defaults to false because normally the only time
     * data is copied into the key is when it's inserted into the session map.
     * @param adopt Flag for whether the new instance should adopt ownership of
     * the key data as-is.
     */
    Key(const void* key_data, size_t size, size_t type, bool copy = false, bool adopt = false);

    ~Key();

    // Implement move semantics for Key, since they're used as keys
    // in a map.
    Key(Key&& rhs);
    Key& operator=(Key&& rhs);

    // Explicitly delete the copy constructor and operator since copying
    // may cause issues with double-freeing pointers.
    Key(const Key& rhs) = delete;
    Key& operator=(const Key& rhs) = delete;

    /**
     * Copy the data pointed at by the data pointer into a new memory location
     * and store it locally. This method is a no-op if the data was already
     * copied.
     */
    void CopyData();

    bool operator<(const Key& rhs) const;
    bool operator==(const Key& rhs) const;

    std::size_t Hash() const { return zeek::detail::HashKey::HashBytes(data, size); }

private:
    friend struct KeyHash;

    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t type = CONNECTION_KEY_TYPE;
    bool owns_data = false;
};

struct KeyHash {
    std::size_t operator()(const Key& k) const { return k.Hash(); }
};

} // namespace zeek::session::detail

namespace zeek {

class Packet;

class RecordVal;
using RecordValPtr = zeek::IntrusivePtr<RecordVal>;

/**
 * Abstract ConnKey - not IP specific.
 *
 * Should move this elsewhere to avoid circular dependencies. Conn really is IP specific,
 * while ConnKey is not.
 */
class ConnKey {
public:
    virtual ~ConnKey() {}

    // Init function called by analyzers or subclassed.
    void Init(const Packet& pkt) { DoInit(pkt); }

    /**
     * Hook method for further initialization.
     *
     * This may also take information from the context.
     *
     * @param p The current packet
     */
    virtual void DoInit(const Packet& pkt) {};

    /**
     * Using this ConnKey and its contents, populate a conn_id or other script layer record.
     */
    virtual void FillConnIdVal(RecordValPtr& conn_id) {};

    /**
     * Populate a ConnKey instance from a script layer record value.
     */
    virtual bool FromConnIdVal(const RecordValPtr& conn_id) = 0;

    /**
     * They Key over which to compute a hash or use for comparison with other keys.
     *
     * The returned Span is only valid as long as this ConnKey instance is valid.
     */
    virtual zeek::Span<const std::byte> Key() const = 0;

    /**
     * View over the key data as a SessionKey.
     *
     * Not sure this makes much sense, it might also be possible to switch
     * the session_map to hold ConnKeyPtr instead with specialized hash and
     * equals functions instead.
     */
    zeek::session::detail::Key SessionKey() const {
        auto span = Key();
        return zeek::session::detail::Key(span.data(), span.size(), session::detail::Key::CONNECTION_KEY_TYPE);
    }

    // Support usage as IntrusivePtr.
    int ref_cnt = 1;
};

inline void Ref(ConnKey* k) { ++k->ref_cnt; }

inline void Unref(ConnKey* k) {
    if ( --k->ref_cnt == 0 )
        delete k;
}

using ConnKeyPtr = zeek::IntrusivePtr<ConnKey>;

} // namespace zeek
