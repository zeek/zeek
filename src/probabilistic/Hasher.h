// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <broker/expected.hh>

#include "zeek/Hash.h"

namespace broker { class data; }

namespace zeek::probabilistic::detail {

/** Types of derived Hasher classes. */
enum HasherType { Default, Double };

/**
 * Abstract base class for hashers. A hasher creates a family of hash
 * functions to hash an element *k* times.
 */
class Hasher {
public:
	typedef zeek::detail::hash_t digest;
	typedef std::vector<digest> digest_vector;
	struct seed_t {
		// actually HH_U64, which has the same type
		alignas(16) unsigned long long h[2];

		friend seed_t operator+(seed_t lhs, const uint64_t rhs) {
			lhs.h[0] += rhs;
			return lhs;
		}
	};

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
	static seed_t MakeSeed(const void* data, size_t size);

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
	digest_vector Hash(const zeek::detail::HashKey* key) const;

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
	seed_t Seed() const	{ return seed; }

	broker::expected<broker::data> Serialize() const;
	static std::unique_ptr<Hasher> Unserialize(const broker::data& data);

protected:
	Hasher() { }

	/**
	 * Constructor.
	 *
	 * @param arg_k the number of hash functions.
	 *
	 * @param arg_seed The seed for the hasher.
	 */
	Hasher(size_t arg_k, seed_t arg_seed);

	virtual HasherType Type() const = 0;

private:
	size_t k;
	seed_t seed;
};

/**
 * A universal hash function family. This is a helper class that Hasher
 * implementations can use in their implementation.
 */
class UHF {
public:
	/**
	 * Default constructor with zero seed.
	 */
	UHF();

	/**
	 * Constructs an hash function seeded with a given seed and an
	 * optional extra seed to replace the initial Bro seed.
	 *
	 * @param arg_seed The seed to use for this instance.
	 */
	explicit UHF(Hasher::seed_t arg_seed);

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
		return (x.seed.h[0] == y.seed.h[0]) &&
		       (x.seed.h[1] == y.seed.h[1]);
		}

	friend bool operator!=(const UHF& x, const UHF& y)
		{
		return ! (x == y);
		}

	broker::expected<broker::data> Serialize() const;
	static UHF Unserialize(const broker::data& data);

private:
	static size_t compute_seed(Hasher::seed_t seed);

	Hasher::seed_t seed;
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
	DefaultHasher(size_t k, Hasher::seed_t seed);

	// Overridden from Hasher.
	digest_vector Hash(const void* x, size_t n) const final;
	DefaultHasher* Clone() const final;
	bool Equals(const Hasher* other) const final;

private:
	DefaultHasher() { }

	HasherType Type() const override
		{ return HasherType::Default; }

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
	DoubleHasher(size_t k, Hasher::seed_t seed);

	// Overridden from Hasher.
	digest_vector Hash(const void* x, size_t n) const final;
	DoubleHasher* Clone() const final;
	bool Equals(const Hasher* other) const final;

private:
	DoubleHasher() { }

	HasherType Type() const override
		{ return HasherType::Double; }

	UHF h1;
	UHF h2;
};

} // namespace zeek::probabilistic::detail
