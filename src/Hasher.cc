#include "Hasher.h"

#include "digest.h"

Hasher::UHF::UHF(size_t seed, const std::string& extra)
	: h_(compute_seed(seed, extra))
	{
	}

Hasher::digest Hasher::UHF::hash(const void* x, size_t n) const
	{
	assert(n <= UHASH_KEY_SIZE);
	return n == 0 ? 0 : h_(x, n);
	}

size_t Hasher::UHF::compute_seed(size_t seed, const std::string& extra)
	{
	u_char buf[SHA256_DIGEST_LENGTH];
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
		sha256_final(&ctx, buf);
		// Take the first sizeof(size_t) bytes as seed.
		return *reinterpret_cast<size_t*>(buf);
		}


Hasher* Hasher::Create(size_t k, const std::string& name)
	{
	return new DefaultHasher(k, name);
	}

Hasher::Hasher(size_t k, const std::string& name)
	: k_(k), name_(name)
	{
	}

DefaultHasher::DefaultHasher(size_t k, const std::string& name)
	: Hasher(k, name)
	{
	for ( size_t i = 0; i < k; ++i )
		hash_functions_.push_back(UHF(i, name));
	}

Hasher::digest_vector DefaultHasher::Hash(const void* x, size_t n) const
	{
	digest_vector h(K(), 0);
	for ( size_t i = 0; i < h.size(); ++i )
		h[i] = hash_functions_[i](x, n);
	return h;
	}

DefaultHasher* DefaultHasher::Clone() const
	{
	return new DefaultHasher(*this);
	}

bool DefaultHasher::Equals(const Hasher* other) const /* final */
	{
	if ( typeid(*this) != typeid(*other) )
		return false;
	const DefaultHasher* o = static_cast<const DefaultHasher*>(other);
	return hash_functions_ == o->hash_functions_;
	}

DoubleHasher::DoubleHasher(size_t k, const std::string& name)
	: Hasher(k, name),
		h1_(1, name),
		h2_(2, name)
	{
	}

Hasher::digest_vector DoubleHasher::Hash(const void* x, size_t n) const
	{
	digest h1 = h1_(x, n);
	digest h2 = h2_(x, n);
	digest_vector h(K(), 0);
	for ( size_t i = 0; i < h.size(); ++i )
		h[i] = h1 + i * h2;
	return h;
	}

DoubleHasher* DoubleHasher::Clone() const
	{
	return new DoubleHasher(*this);
	}

bool DoubleHasher::Equals(const Hasher* other) const /* final */
	{
	if ( typeid(*this) != typeid(*other) )
		return false;
	const DoubleHasher* o = static_cast<const DoubleHasher*>(other);
	return h1_ == o->h1_ && h2_ == o->h2_;
	}

