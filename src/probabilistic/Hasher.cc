// See the file "COPYING" in the main distribution directory for copyright.

#include <typeinfo>

#include "Hasher.h"
#include "digest.h"

using namespace probabilistic;

UHF::UHF(size_t seed, const std::string& extra)
	: h(compute_seed(seed, extra))
	{
	}

Hasher::digest UHF::hash(const void* x, size_t n) const
	{
	assert(n <= UHASH_KEY_SIZE);
	return n == 0 ? 0 : h(x, n);
	}

size_t UHF::compute_seed(size_t seed, const std::string& extra)
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
		sha256_update(&ctx, extra.c_str(), extra.size());

	sha256_update(&ctx, &seed, sizeof(seed));
	sha256_final(&ctx, buf);

	// Take the first sizeof(size_t) bytes as seed.
	return *reinterpret_cast<size_t*>(buf);
	}

Hasher* Hasher::Create(size_t k, const std::string& name)
	{
	return new DefaultHasher(k, name);
	}

Hasher::Hasher(size_t k, const std::string& arg_name)
	: k(k)
	{
	name = arg_name;
	}

DefaultHasher::DefaultHasher(size_t k, const std::string& name)
	: Hasher(k, name)
	{
	for ( size_t i = 0; i < k; ++i )
		hash_functions.push_back(UHF(i, name));
	}

Hasher::digest_vector DefaultHasher::Hash(const void* x, size_t n) const
	{
	digest_vector h(K(), 0);

	for ( size_t i = 0; i < h.size(); ++i )
		h[i] = hash_functions[i](x, n);

	return h;
	}

DefaultHasher* DefaultHasher::Clone() const
	{
	return new DefaultHasher(*this);
	}

bool DefaultHasher::Equals(const Hasher* other) const
	{
	if ( typeid(*this) != typeid(*other) )
		return false;

	const DefaultHasher* o = static_cast<const DefaultHasher*>(other);
	return hash_functions == o->hash_functions;
	}

DoubleHasher::DoubleHasher(size_t k, const std::string& name)
	: Hasher(k, name), h1(1, name), h2(2, name)
	{
	}

Hasher::digest_vector DoubleHasher::Hash(const void* x, size_t n) const
	{
	digest d1 = h1(x, n);
	digest d2 = h2(x, n);
	digest_vector h(K(), 0);

	for ( size_t i = 0; i < h.size(); ++i )
		h[i] = d1 + i * d2;

	return h;
	}

DoubleHasher* DoubleHasher::Clone() const
	{
	return new DoubleHasher(*this);
	}

bool DoubleHasher::Equals(const Hasher* other) const
	{
	if ( typeid(*this) != typeid(*other) )
		return false;

	const DoubleHasher* o = static_cast<const DoubleHasher*>(other);
	return h1 == o->h1 && h2 == o->h2;
	}
