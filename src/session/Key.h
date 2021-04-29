// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <cstdint>

namespace zeek::session::detail {

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

	/**
	 * Create a new session key from a data pointer.
	 *
	 * @param session A pointer to the data for the key.
	 * @param size The size of the key data, in bytes.
	 * @param copy Flag for whether the data should be copied into the Key
	 * during construction. This defaults to false because normally the only time
	 * data is copied into the key is when it's inserted into the session map.
	 */
	Key(const void* key_data, size_t size, bool copy=false);

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

private:
	const uint8_t* data = nullptr;
	size_t size = 0;
	bool copied = false;
};

} // namespace zeek::session::detail
