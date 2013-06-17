#ifndef HashPolicy_h
#define HashPolicy_h

#include "Hash.h"
#include "H3.h"

/**
 * A functor that computes a universal hash function.
 */
class Hasher {
public:
	typedef hash_t hash_type;

	/**
	 * Constructs a hasher seeded by a given seed and optionally an extra
	 * descriptor.
	 *
	 * @param seed The seed to use.
	 *
	 * @param extra If not `NULL`, the hasher will not mix in the initial seed
	 * but instead use this NUL-terminated string as additional seed.
	 */
	Hasher(size_t seed, const std::string& extra = "");

	/**
	 * Computes the hash digest of contiguous data.
	 *
	 * @param x A pointer to the beginning of the byte sequence to hash.
	 *
	 * @param n The length of the sequence pointed to by *x*.
	 */
	hash_type operator()(const void* x, size_t n) const;

private:
	static size_t compute_seed(size_t seed, const std::string& extra);

	H3<hash_type, UHASH_KEY_SIZE> h_;
};

/**
 * The abstract base class for hash policies that hash elements *k* times.
 */
class HashPolicy {
public:
  /**
   * Constructs the hashing policy used by the implementation. This factory
   * function exists because the HashingPolicy class hierachy is not yet
   * serializable.
   */
	static HashPolicy* Create(size_t k, const std::string& name);

  typedef Hasher::hash_type hash_type;
  typedef std::vector<hash_type> hash_vector;

  virtual ~HashPolicy() { }

  virtual hash_vector Hash(const void* x, size_t n) const = 0;

  size_t K() const { return k_; }
  const std::string& Name() const { return name_; }

protected:
  HashPolicy(size_t k, const std::string& name);

private:
  const size_t k_;
  std::string name_;
};

/**
 * The default hashing policy. Performs *k* hash function computations.
 */
class DefaultHashing : public HashPolicy {
public:
  DefaultHashing(size_t k, const std::string& name);

  virtual hash_vector Hash(const void* x, size_t n) const /* override */;

private:
  std::vector<Hasher> hashers_;
};

/**
 * The *double-hashing* policy. Uses a linear combination of two hash functions.
 */
class DoubleHashing : public HashPolicy {
public:
  DoubleHashing(size_t k, const std::string& name);

  virtual hash_vector Hash(const void* x, size_t n) const;

private:
  Hasher hasher1_;
  Hasher hasher2_;
};

#endif
