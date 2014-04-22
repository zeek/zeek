// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PROBABILISTIC_HASHER_H
#define PROBABILISTIC_HASHER_H

#include "Hash.h"
#include "H3.h"
#include "SerialObj.h"

namespace probabilistic {

/**
 * Abstract base class for hashers. A hasher creates a family of hash
 * functions to hash an element *k* times.
 */
class Hasher : public SerialObj {
public:
	typedef hash_t digest;
	typedef std::vector<digest> digest_vector;

	/**
	 * Creates a valid hasher seed from an arbitrary string.
	 *
	 * @param data A pointer to contiguous data that should be crunched into a
	 * seed. If 0, the function tries to find a global_hash_seed script variable
	 * to derive a seed from. If this variable does not exist, the function uses
	 * the initial seed generated at Bro startup.
	 *
	 * @param size The number of bytes of *data*.
	 *
	 * @return A seed suitable for hashers.
	 */
	static uint64 MakeSeed(const void* data, size_t size);

	/**
	 * Destructor.
	 */
	virtual ~Hasher() { }

	/**
	 * Computes hash values for an element.
	 *
	 * @param x The element to hash.
	 *
	 * @return Vector of *k* hash values.
	 */
	template <typename T>
	digest_vector operator()(const T& x) const
		{
		return Hash(&x, sizeof(T));
		}

	/**
	 * Computes hash values for an element.
	 *
	 * @param x The key of the value to hash.
	 *
	 * @return Vector of *k* hash values.
	 */
	digest_vector Hash(const HashKey* key) const;

	/**
	 * Computes the hashes for a set of bytes.
	 *
	 * @param x Pointer to first byte to hash.
	 *
	 * @param n Number of bytes to hash.
	 *
	 * @return Vector of *k* hash values.
	 *
	 */
	virtual digest_vector Hash(const void* x, size_t n) const = 0;

	/**
	 * Returns a deep copy of the hasher.
	 */
	virtual Hasher* Clone() const = 0;

	/**
	 * Returns true if two hashers are identical.
	 */
	virtual bool Equals(const Hasher* other) const = 0;

	/**
	 * Returns the number *k* of hash functions the hashers applies.
	 */
	size_t K() const	{ return k; }

	/**
	 * Returns the seed used to construct the hasher.
	 */
	size_t Seed() const	{ return seed; }

	bool Serialize(SerialInfo* info) const;
	static Hasher* Unserialize(UnserialInfo* info);

protected:
	DECLARE_ABSTRACT_SERIAL(Hasher);

	Hasher() { }

	/**
	 * Constructor.
	 *
	 * @param arg_k the number of hash functions.
	 *
	 * @param arg_seed The seed for the hasher.
	 */
	Hasher(size_t arg_k, size_t arg_seed);

private:
	size_t k;
	size_t seed;
};

/**
 * A universal hash function family. This is a helper class that Hasher
 * implementations can use in their implementation.
 */
class UHF {
public:
	/**
	 * Constructs an H3 hash function seeded with a given seed and an
	 * optional extra seed to replace the initial Bro seed.
	 *
	 * @param arg_seed The seed to use for this instance.
	 */
	UHF(size_t arg_seed = 0);

	template <typename T>
	Hasher::digest operator()(const T& x) const
		{
		return hash(&x, sizeof(T));
		}

	/**
	 * Computes hash values for an element.
	 *
	 * @param x The element to hash.
	 *
	 * @return Vector of *k* hash values.
	 */
	Hasher::digest operator()(const void* x, size_t n) const
		{
		return hash(x, n);
		}

	/**
	 * Computes the hashes for a set of bytes.
	 *
	 * @param x Pointer to first byte to hash.
	 *
	 * @param n Number of bytes to hash.
	 *
	 * @return Vector of *k* hash values.
	 *
	 */
	Hasher::digest hash(const void* x, size_t n) const;

	friend bool operator==(const UHF& x, const UHF& y)
		{
		return x.h == y.h;
		}

	friend bool operator!=(const UHF& x, const UHF& y)
		{
		return ! (x == y);
		}

private:
	static size_t compute_seed(size_t seed);

	H3<Hasher::digest, UHASH_KEY_SIZE> h;
	size_t seed;
};


/**
 * A hasher implementing the default hashing policy. Uses *k* separate hash
 * functions internally.
 */
class DefaultHasher : public Hasher {
public:
	/**
	 * Constructor for a hasher with *k* hash functions.
	 *
	 * @param k The number of hash functions to use.
	 *
	 * @param seed The seed for the hasher.
	 */
	DefaultHasher(size_t k, size_t seed);

	// Overridden from Hasher.
	virtual digest_vector Hash(const void* x, size_t n) const /* final */;
	virtual DefaultHasher* Clone() const /* final */;
	virtual bool Equals(const Hasher* other) const /* final */;

	DECLARE_SERIAL(DefaultHasher);

private:
	DefaultHasher() { }

	std::vector<UHF> hash_functions;
};

/**
 * The *double-hashing* policy. Uses a linear combination of two hash
 * functions.
 */
class DoubleHasher : public Hasher {
public:
	/**
	 * Constructor for a double hasher with *k* hash functions.
	 *
	 * @param k The number of hash functions to use.
	 *
	 * @param seed The seed for the hasher.
	 */
	DoubleHasher(size_t k, size_t seed);

	// Overridden from Hasher.
	virtual digest_vector Hash(const void* x, size_t n) const /* final */;
	virtual DoubleHasher* Clone() const /* final */;
	virtual bool Equals(const Hasher* other) const /* final */;

	DECLARE_SERIAL(DoubleHasher);

private:
	DoubleHasher() { }

	UHF h1;
	UHF h2;
};

}

#endif
