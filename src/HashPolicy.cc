#include "HashPolicy.h"

#include "digest.h"

Hasher::Hasher(size_t seed, const std::string& extra)
	: h_(compute_seed(seed, extra))
	{
	}

Hasher::hash_type Hasher::operator()(const void* x, size_t n) const
  {
  return n == 0 ? 0 : h_(x, n);
  }

size_t Hasher::compute_seed(size_t seed, const std::string& extra)
  {
  u_char digest[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  sha256_init(&ctx);
  if ( extra.empty() )
		{
		unsigned int first_seed = initial_seed();
		sha256_update(&ctx, &first_seed, sizeof(first_seed));
		}
	else
		{
    sha256_update(&ctx, extra.c_str(), extra.size());
		}
  sha256_update(&ctx, &seed, sizeof(seed));
  sha256_final(&ctx, digest);
  return *reinterpret_cast<size_t*>(digest);
  }


HashPolicy* HashPolicy::Create(size_t k, const std::string& name)
  {
  return new DefaultHashing(k, name);
  }

HashPolicy::HashPolicy(size_t k, const std::string& name)
  : k_(k), name_(name)
	{
	}

DefaultHashing::DefaultHashing(size_t k, const std::string& name)
  : HashPolicy(k, name)
  {
  for ( size_t i = 0; i < k; ++i )
    hashers_.push_back(Hasher(i, name));
  }

HashPolicy::hash_vector DefaultHashing::Hash(const void* x, size_t n) const
  {
  hash_vector h(K(), 0);
  for ( size_t i = 0; i < h.size(); ++i )
    h[i] = hashers_[i](x, n);
  return h;
  }

DoubleHashing::DoubleHashing(size_t k, const std::string& name)
	: HashPolicy(k, name),
		hasher1_(1, name),
		hasher2_(2, name)
	{
	}

HashPolicy::hash_vector DoubleHashing::Hash(const void* x, size_t n) const
  {
  hash_type h1 = hasher1_(x, n);
  hash_type h2 = hasher2_(x, n);
  hash_vector h(K(), 0);
  for ( size_t i = 0; i < h.size(); ++i )
    h[i] = h1 + i * h2;
  return h;
  }


