// See the file "COPYING" in the main distribution directory for copyright.

#ifndef BRO_UID_H
#define BRO_UID_H

#include <string>
#include <vector>

#include "util.h"

namespace Bro {

/**
 * A class for creating/managing UIDs of arbitrary bit-length and converting
 * them to human-readable strings in Base62 format.
 */
class UID {
public:

	/**
	 * Default ctor.  The UID is uninitialized and in string format is
	 * represented by an empty string.
	 */
	UID() {}

	/**
	 * Construct a UID of a given bit-length, optionally from given values.
	 * @see UID::Set
	 */
	UID(bro_uint_t bits, const std::vector<uint64>& v = std::vector<uint64>())
		{ Set(bits, v); }

	/**
	 * Copy constructor.
	 */
	UID(const UID& other) { uid = other.uid; }

	/**
	 * Inititialize a UID of a given bit-length, optionally from given values.
	 * @param bits The desired length in bits of the UID.
	 * @param v A vector of values with which to initialize the UID.
	 *          If empty or doesn't contain enough values to satisfy \a bits,
	 *          then values are automatically generated using
	 *          calculate_unique_id().  If \a bits isn't evenly divisible by
	 *          64, then a value is truncated to bit in desired bit-length.
	 */
	void Set(bro_uint_t bits,
	         const std::vector<uint64>& v = std::vector<uint64>());

	/**
	 * Returns a base62 (characters 0-9, A-Z, a-z) representation of the UID.
	 * @param prefix An optional string prefix.
	 * @return a base62 string representing the UID.
	 */
	std::string Base62(const std::string& prefix = "") const;

	/**
	 * @return false if the UID instance was created via the default ctor
	 *         and not yet initialized w/ Set().
	 * TODO: this would be better as an "explicit" conversion operator (C++11)
	 */
	operator bool() const { return ( ! uid.empty() ); }

	/**
	 * Assignment operator.
	 */
	UID& operator=(const UID& other) { uid = other.uid; return *this; }

	/**
	 * UID equality operator.
	 */
	friend bool operator==(const UID& u1, const UID& u2);

	/**
	 * UID inequality operator.
	 */
	friend bool operator!=(const UID& u1, const UID& u2)
		{ return ! ( u1 == u2 ); }

private:
	std::vector<uint64> uid;
};

bool operator==(const UID& u1, const UID& u2);

} // namespace Bro

#endif
