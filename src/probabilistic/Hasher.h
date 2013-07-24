// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PROBABILISTIC_HASHER_H
#define PROBABILISTIC_HASHER_H

#include "Hash.h"
#include "H3.h"

namespace probabilistic {

/**
 * Abstract base class for hashers. A hasher creates a family of hash
 * functions to hash an element *k* times.
 */
class Hasher {
public:
	typedef hash_t digest;
	typedef std::vector<digest> digest_vector;

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
	 * Returns the hasher's name. TODO: What's this?
	 */
	const std::string& Name() const { return name; }

	/**
	 * Constructs the hasher used by the implementation. This hardcodes a
	 * specific hashing policy. It exists only because the HashingPolicy
	 * class hierachy is not yet serializable.
	 *
	 * @param k The number of hash functions to apply.
	 *
	 * @param name The hasher's name. Hashers with the same name should
	 * provide consistent results.
	 *
	 * @return Returns a new hasher instance.
	 */
	static Hasher* Create(size_t k, const std::string& name);

protected:
	/**
	 * Constructor.
	 *
	 * @param k the number of hash functions.
	 *
	 * @param name A name for the hasher. Hashers with the same name
	 * should provide consistent results.
	 */
	Hasher(size_t k, const std::string& name);

private:
	const size_t k;
	std::string name;
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
	 * @param seed The seed to use for this instance.
	 *
	 * @param extra If not empty, this parameter replaces the initial
	 * seed to compute the seed for t to compute the seed NUL-terminated
	 * string as additional seed.
	 */
	UHF(size_t seed, const std::string& extra = "");

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
	static size_t compute_seed(size_t seed, const std::string& extra);

	H3<Hasher::digest, UHASH_KEY_SIZE> h;
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
	 * @param name The name of the hasher.
	 */
	DefaultHasher(size_t k, const std::string& name);

	// Overridden from Hasher.
	virtual digest_vector Hash(const void* x, size_t n) const /* final */;
	virtual DefaultHasher* Clone() const /* final */;
	virtual bool Equals(const Hasher* other) const /* final */;

private:
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
	 * @param name The name of the hasher.
	 */
	DoubleHasher(size_t k, const std::string& name);

	// Overridden from Hasher.
	virtual digest_vector Hash(const void* x, size_t n) const /* final */;
	virtual DoubleHasher* Clone() const /* final */;
	virtual bool Equals(const Hasher* other) const /* final */;

private:
	UHF h1;
	UHF h2;
};

}

#endif
