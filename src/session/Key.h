// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "zeek/Hash.h"
#include "zeek/IntrusivePtr.h"

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
 */
class ConnKey {
public:
    virtual ~ConnKey() {}

    /**
     * Initialization of this key with the current packet.
     */
    void Init(const Packet& pkt) { DoInit(pkt); }

    /**
     * Given the ConnKey, fill a script layer record with
     * its custom information. E.g. VLAN.
     *
     * Empty implementation by default.
     */
    virtual void FillConnIdVal(RecordValPtr& conn_id) {};

    /**
     * Return a non-owning session::detail::Key instance.
     *
     * Callers that need more than a View should copy
     * the data. Callers are not supposed to hold on
     * to the Key for longer than the ConnKey instance
     * exists. Think string_view or span!
     *
     * @return A zeek::session::detail::Key
     */
    virtual zeek::session::detail::Key SessionKey() const = 0;

    /**
     * Get the error state of a ConnKey, if any.
     *
     * Instances of a ConnKey created from zeek::Val instances
     * via Builder::FromVal() may not be valid. Calling Error()
     * can be used to gather a description of the encountered
     * error.
     */
    virtual std::optional<std::string> Error() const = 0;

protected:
    /**
     * Hook method for custom initialization.
     *
     * This may also take information from the global context rather
     * than just the packet.
     *
     * @param p The current packet
     */
    virtual void DoInit(const Packet& pkt) {};
};

using ConnKeyPtr = std::unique_ptr<ConnKey>;

} // namespace zeek
