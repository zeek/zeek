// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BRO_UID_H
#define BRO_UID_H

#include <string>

#include "Reporter.h"
#include "util.h"

#define BRO_UID_LEN 2

namespace Bro {

/**
 * A class for creating/managing UIDs of arbitrary bit-length and converting
 * them to human-readable strings in Base62 format.
 */
class UID {
public:

	/**
	 * Default ctor.  The UID is uninitialized.
	 */
	UID() : initialized(false) {}

	/**
	 * Construct a UID of a given bit-length, optionally from given values.
	 * @see UID::Set
	 */
	UID(bro_uint_t bits, const uint64* v = 0, size_t n = 0)
		{ Set(bits, v, n); }

	/**
	 * Copy constructor.
	 */
	UID(const UID& other);

	/**
	 * Inititialize a UID of a given bit-length, optionally from given values.
	 * @param bits The desired length in bits of the UID, up to a max of
	 *             BRO_UID_LEN * 64.
	 * @param v A pointer to an array of values with which to initialize the
	 *          UID.  If empty or doesn't contain enough values to satisfy
	 *          \a bits, then values are automatically generated using
	 *          calculate_unique_id().  If \a bits isn't evenly divisible by
	 *          64, then a value is truncated to bit in desired bit-length.
	 * @param n number of 64-bit elements in array pointed to by \a v.
	 */
	void Set(bro_uint_t bits, const uint64* v = 0, size_t n = 0);

	/**
	 * Returns a base62 (characters 0-9, A-Z, a-z) representation of the UID.
	 * @param prefix An optional string prefix.
	 * @return a base62 string representing the UID.
	 */
	std::string Base62(std::string prefix = "") const;

	/**
	 * @return false if the UID instance was created via the default ctor
	 *         and not yet initialized w/ Set().
	 * TODO: this would be better as an "explicit" conversion operator (C++11)
	 */
	operator bool() const
		{ return initialized; }

	/**
	 * Assignment operator.
	 */
	UID& operator=(const UID& other);

	/**
	 * UID equality operator.
	 */
	friend bool operator==(const UID& u1, const UID& u2)
		{ return memcmp(u1.uid, u2.uid, sizeof(u1.uid)) == 0; }

	/**
	 * UID inequality operator.
	 */
	friend bool operator!=(const UID& u1, const UID& u2)
		{ return ! ( u1 == u2 ); }

private:
	uint64 uid[BRO_UID_LEN];
	bool initialized; // Since technically uid == 0 is a legit UID
};

inline UID::UID(const UID& other)
	{
	memcpy(uid, other.uid, sizeof(uid));
	initialized = other.initialized;
	}

inline UID& UID::operator=(const UID& other)
	{
	memmove(uid, other.uid, sizeof(uid));
	initialized = other.initialized;
	return *this;
	}

inline std::string UID::Base62(std::string prefix) const
	{
	if ( ! initialized )
		reporter->InternalError("use of uninitialized UID");

	char tmp[sizeof(uid) * 8 + 1];  // enough for even binary representation
	for ( size_t i = 0; i < BRO_UID_LEN; ++i )
		prefix.append(uitoa_n(uid[i], tmp, sizeof(tmp), 62));

	return prefix;
	}

} // namespace Bro

#endif
