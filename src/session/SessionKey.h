// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <cstdint>

namespace zeek::session::detail {

/**
 * This type is used as the key for the map in SessionManager. It represents a
 * raw block of memory that points to a key of some type for a session, such as
 * a ConnIDKey for a Connection. This allows us to do type-independent
 * comparison of the keys in the map. By default, this type does not maintain
 * the lifetime of the data pointed to by the SessionKey. It only holds a
 * pointer. When a SessionKey object is inserted into the SessionManager's map,
 * the data is copied into the object so the lifetime of the key data is
 * guaranteed over the lifetime of the map entry.
 */
class SessionKey final {
public:

	/**
	 * Create a new session key from a data pointer.
	 *
	 * @param session A pointer to the data for the key.
	 * @param size The size of the key data, in bytes.
	 * @param copy Flag for whether the data should be copied into the SessionKey
	 * during construction. This defaults to false because normally the only time
	 * data is copied into the key is when it's inserted into the session map.
	 */
	SessionKey(const void* key_data, size_t size, bool copy=false);

	~SessionKey();

	// Implement move semantics for SessionKey, since they're used as keys
	// in a map.
	SessionKey(SessionKey&& rhs);
	SessionKey& operator=(SessionKey&& rhs);

	// Explicitly delete the copy constructor and operator since copying
	// may cause issues with double-freeing pointers.
	SessionKey(const SessionKey& rhs) = delete;
	SessionKey& operator=(const SessionKey& rhs) = delete;

	/**
	 * Copy the data pointed at by the data pointer into a new memory location
	 * and store it locally. This method is a no-op if the data was already
	 * copied.
	 */
	void CopyData();

	bool operator<(const SessionKey& rhs) const;

private:
	const uint8_t* data = nullptr;
	size_t size = 0;
	bool copied = false;
};

} // namespace zeek::session::detail
