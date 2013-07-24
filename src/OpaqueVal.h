// See the file "COPYING" in the main distribution directory for copyright.

#ifndef OPAQUEVAL_H
#define OPAQUEVAL_H

#include <typeinfo>

#include "RandTest.h"
#include "Val.h"
#include "digest.h"

#include "probabilistic/BloomFilter.h"

namespace probabilistic {
	class BloomFilter;
}

class HashVal : public OpaqueVal {
public:
	virtual bool IsValid() const;
	virtual bool Init();
	virtual bool Feed(const void* data, size_t size);
	virtual StringVal* Get();

protected:
	HashVal() { };
	HashVal(OpaqueType* t);
	virtual bool DoInit();
	virtual bool DoFeed(const void* data, size_t size);
	virtual StringVal* DoGet();

	DECLARE_SERIAL(HashVal);

private:
	// This flag exists because Get() can only be called once.
	bool valid;
};

class MD5Val : public HashVal {
public:
	static void digest(val_list& vlist, u_char result[MD5_DIGEST_LENGTH]);

	static void hmac(val_list& vlist,
			 u_char key[MD5_DIGEST_LENGTH],
			 u_char result[MD5_DIGEST_LENGTH]);

	MD5Val();

protected:
	friend class Val;

	virtual bool DoInit() /* override */;
	virtual bool DoFeed(const void* data, size_t size) /* override */;
	virtual StringVal* DoGet() /* override */;

	DECLARE_SERIAL(MD5Val);

private:
	MD5_CTX ctx;
};

class SHA1Val : public HashVal {
public:
	static void digest(val_list& vlist, u_char result[SHA_DIGEST_LENGTH]);

	SHA1Val();

protected:
	friend class Val;

	virtual bool DoInit() /* override */;
	virtual bool DoFeed(const void* data, size_t size) /* override */;
	virtual StringVal* DoGet() /* override */;

	DECLARE_SERIAL(SHA1Val);

private:
	SHA_CTX ctx;
};

class SHA256Val : public HashVal {
public:
	static void digest(val_list& vlist, u_char result[SHA256_DIGEST_LENGTH]);

	SHA256Val();

protected:
	friend class Val;

	virtual bool DoInit() /* override */;
	virtual bool DoFeed(const void* data, size_t size) /* override */;
	virtual StringVal* DoGet() /* override */;

	DECLARE_SERIAL(SHA256Val);

private:
	SHA256_CTX ctx;
};

class EntropyVal : public OpaqueVal {
public:
	EntropyVal();

	bool Feed(const void* data, size_t size);
	bool Get(double *r_ent, double *r_chisq, double *r_mean,
		 double *r_montepicalc, double *r_scc);

protected:
	friend class Val;
	EntropyVal(OpaqueType* t);

	DECLARE_SERIAL(EntropyVal);

private:
	RandTest state;
};

class BloomFilterVal : public OpaqueVal {
public:
	explicit BloomFilterVal(probabilistic::BloomFilter* bf);
	virtual ~BloomFilterVal();

	BroType* Type() const;
	bool Typify(BroType* type);

	void Add(const Val* val);
	size_t Count(const Val* val) const;

	static BloomFilterVal* Merge(const BloomFilterVal* x,
				     const BloomFilterVal* y);

protected:
	friend class Val;
	BloomFilterVal();
	BloomFilterVal(OpaqueType* t);

	DECLARE_SERIAL(BloomFilterVal);

private:
	// Disable.
	BloomFilterVal(const BloomFilterVal&);
	BloomFilterVal& operator=(const BloomFilterVal&);

	template <typename T>
	static BloomFilterVal* DoMerge(const BloomFilterVal* x,
				       const BloomFilterVal* y)
		{
		if ( typeid(*x->bloom_filter) != typeid(*y->bloom_filter) )
			reporter->InternalError("cannot merge different Bloom filter types");

		if ( typeid(T) != typeid(*x->bloom_filter) )
			return 0;

		const T* a = static_cast<const T*>(x->bloom_filter);
		const T* b = static_cast<const T*>(y->bloom_filter);

		BloomFilterVal* merged = new BloomFilterVal(T::Merge(a, b));
		assert(merged);

		if ( ! merged->Typify(x->Type()) )
			reporter->InternalError("failed to set type on merged Bloom filter");

		return merged;
		}

	BroType* type;
	CompositeHash* hash;
	probabilistic::BloomFilter* bloom_filter;
	};

#endif
