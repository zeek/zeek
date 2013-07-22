#ifndef Hasher_h
#define Hasher_h

#include "Hash.h"
#include "H3.h"

/**
 * The abstract base class for hashers, i.e., constructs which hash elements
 * *k* times.
 */
class Hasher {
public:
  typedef hash_t digest;
  typedef std::vector<digest> digest_vector;

  /**
   * Constructs the hashing policy used by the implementation. 
   *
   * @todo This factory function exists because the HashingPolicy class
   * hierachy is not yet serializable.
   */
	static Hasher* Create(size_t k, const std::string& name);

  virtual ~Hasher() { }

  template <typename T>
  digest_vector operator()(const T& x) const
  {
    return Hash(&x, sizeof(T));
  }

  virtual digest_vector Hash(const void* x, size_t n) const = 0;

  virtual Hasher* Clone() const = 0;

  virtual bool Equals(const Hasher* other) const = 0;

  size_t K() const { return k_; }
  const std::string& Name() const { return name_; }

protected:
  /** 
   * A universal hash function family.
   */
  class UHF {
  public:
    /**
     * Constructs an H3 hash function seeded with a given seed and an optional
     * extra seed to replace the initial Bro seed.
     *
     * @param seed The seed to use for this instance.
     *
     * @param extra If not empty, this parameter replaces the initial seed to
     * compute the seed for t to compute the
     * seed
     * NUL-terminated string as additional seed.
     */
    UHF(size_t seed, const std::string& extra = "");

    template <typename T>
    digest operator()(const T& x) const
    {
      return hash(&x, sizeof(T));
    }

    digest operator()(const void* x, size_t n) const
    {
      return hash(x, n);
    }

    friend bool operator==(const UHF& x, const UHF& y)
    {
      return x.h_ == y.h_;
    }

    friend bool operator!=(const UHF& x, const UHF& y)
    {
      return ! (x == y);
    }

    digest hash(const void* x, size_t n) const;

  private:
    static size_t compute_seed(size_t seed, const std::string& extra);

    H3<digest, UHASH_KEY_SIZE> h_;
  };

  Hasher(size_t k, const std::string& name);

private:
  const size_t k_;
  std::string name_;
};

/**
 * The default hashing policy. Performs *k* hash function computations.
 */
class DefaultHasher : public Hasher {
public:
  DefaultHasher(size_t k, const std::string& name);

  virtual digest_vector Hash(const void* x, size_t n) const /* final */;
  virtual DefaultHasher* Clone() const /* final */;
  virtual bool Equals(const Hasher* other) const /* final */;

private:
  std::vector<UHF> hash_functions_;
};

/**
 * The *double-hashing* policy. Uses a linear combination of two hash functions.
 */
class DoubleHasher : public Hasher {
public:
  DoubleHasher(size_t k, const std::string& name);

  virtual digest_vector Hash(const void* x, size_t n) const /* final */;
  virtual DoubleHasher* Clone() const /* final */;
  virtual bool Equals(const Hasher* other) const /* final */;

private:
  UHF h1_;
  UHF h2_;
};

#endif
