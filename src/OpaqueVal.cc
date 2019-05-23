// See the file "COPYING" in the main distribution directory for copyright.

#include "OpaqueVal.h"
#include "NetVar.h"
#include "Reporter.h"
#include "probabilistic/BloomFilter.h"
#include "probabilistic/CardinalityCounter.h"

bool HashVal::IsValid() const
	{
	return valid;
	}

bool HashVal::Init()
	{
	if ( valid )
		return false;

	valid = DoInit();
	return valid;
	}

StringVal* HashVal::Get()
	{
	if ( ! valid )
		return val_mgr->GetEmptyString();

	StringVal* result = DoGet();
	valid = false;
	return result;
	}

bool HashVal::Feed(const void* data, size_t size)
	{
	if ( valid )
		return DoFeed(data, size);

	Error("attempt to update an invalid opaque hash value");
	return false;
	}

bool HashVal::DoInit()
	{
	assert(! "missing implementation of DoInit()");
	return false;
	}

bool HashVal::DoFeed(const void*, size_t)
	{
	assert(! "missing implementation of DoFeed()");
	return false;
	}

StringVal* HashVal::DoGet()
	{
	assert(! "missing implementation of DoGet()");
	return val_mgr->GetEmptyString();
	}

HashVal::HashVal(OpaqueType* t) : OpaqueVal(t)
	{
	valid = false;
	}

MD5Val::MD5Val() : HashVal(md5_type)
	{
	}

MD5Val::~MD5Val()
	{
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
	}

Val* MD5Val::DoClone(CloneState* state)
	{
	auto out = new MD5Val();
	if ( IsValid() )
		{
		if ( ! out->Init() )
			return nullptr;
		EVP_MD_CTX_copy_ex(out->ctx, ctx);
		}

	return out;
	}

void MD5Val::digest(val_list& vlist, u_char result[MD5_DIGEST_LENGTH])
	{
	EVP_MD_CTX* h = hash_init(Hash_MD5);

	loop_over_list(vlist, i)
		{
		Val* v = vlist[i];
		if ( v->Type()->Tag() == TYPE_STRING )
			{
			const BroString* str = v->AsString();
			hash_update(h, str->Bytes(), str->Len());
			}
		else
			{
			ODesc d(DESC_BINARY);
			v->Describe(&d);
			hash_update(h, (const u_char *) d.Bytes(), d.Len());
			}
		}

	hash_final(h, result);
	}

void MD5Val::hmac(val_list& vlist,
                  u_char key[MD5_DIGEST_LENGTH],
                  u_char result[MD5_DIGEST_LENGTH])
	{
	digest(vlist, result);
	for ( int i = 0; i < MD5_DIGEST_LENGTH; ++i )
		result[i] ^= key[i];

	internal_md5(result, MD5_DIGEST_LENGTH, result);
	}

bool MD5Val::DoInit()
	{
	assert(! IsValid());
	ctx = hash_init(Hash_MD5);
	return true;
	}

bool MD5Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	hash_update(ctx, data, size);
	return true;
	}

StringVal* MD5Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->GetEmptyString();

	u_char digest[MD5_DIGEST_LENGTH];
	hash_final(ctx, digest);
	return new StringVal(md5_digest_print(digest));
	}

SHA1Val::SHA1Val() : HashVal(sha1_type)
	{
	}

SHA1Val::~SHA1Val()
	{
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
	}

Val* SHA1Val::DoClone(CloneState* state)
	{
	auto out = new SHA1Val();
	if ( IsValid() )
		{
		if ( ! out->Init() )
			return nullptr;
		EVP_MD_CTX_copy_ex(out->ctx, ctx);
		}

	return out;
	}

void SHA1Val::digest(val_list& vlist, u_char result[SHA_DIGEST_LENGTH])
	{
	EVP_MD_CTX* h = hash_init(Hash_SHA1);

	loop_over_list(vlist, i)
		{
		Val* v = vlist[i];
		if ( v->Type()->Tag() == TYPE_STRING )
			{
			const BroString* str = v->AsString();
			hash_update(h, str->Bytes(), str->Len());
			}
		else
			{
			ODesc d(DESC_BINARY);
			v->Describe(&d);
			hash_update(h, (const u_char *) d.Bytes(), d.Len());
			}
		}

	hash_final(h, result);
	}

bool SHA1Val::DoInit()
	{
	assert(! IsValid());
	ctx = hash_init(Hash_SHA1);
	return true;
	}

bool SHA1Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	hash_update(ctx, data, size);
	return true;
	}

StringVal* SHA1Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->GetEmptyString();

	u_char digest[SHA_DIGEST_LENGTH];
	hash_final(ctx, digest);
	return new StringVal(sha1_digest_print(digest));
	}

SHA256Val::SHA256Val() : HashVal(sha256_type)
	{
	}

SHA256Val::~SHA256Val()
	{
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
	}

Val* SHA256Val::DoClone(CloneState* state)
	{
	auto out = new SHA256Val();
	if ( IsValid() )
		{
		if ( ! out->Init() )
			return nullptr;
		EVP_MD_CTX_copy_ex(out->ctx, ctx);
		}

	return out;
	}

void SHA256Val::digest(val_list& vlist, u_char result[SHA256_DIGEST_LENGTH])
	{
	EVP_MD_CTX* h = hash_init(Hash_SHA256);

	loop_over_list(vlist, i)
		{
		Val* v = vlist[i];
		if ( v->Type()->Tag() == TYPE_STRING )
			{
			const BroString* str = v->AsString();
			hash_update(h, str->Bytes(), str->Len());
			}
		else
			{
			ODesc d(DESC_BINARY);
			v->Describe(&d);
			hash_update(h, (const u_char *) d.Bytes(), d.Len());
			}
		}

	hash_final(h, result);
	}

bool SHA256Val::DoInit()
	{
	assert( ! IsValid() );
	ctx = hash_init(Hash_SHA256);
	return true;
	}

bool SHA256Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	hash_update(ctx, data, size);
	return true;
	}

StringVal* SHA256Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->GetEmptyString();

	u_char digest[SHA256_DIGEST_LENGTH];
	hash_final(ctx, digest);
	return new StringVal(sha256_digest_print(digest));
	}

EntropyVal::EntropyVal() : OpaqueVal(entropy_type)
	{
	}

Val* EntropyVal::DoClone(CloneState* state)
	{
	// Fixme
	return nullptr;
	}

bool EntropyVal::Feed(const void* data, size_t size)
	{
	state.add(data, size);
	return true;
	}

bool EntropyVal::Get(double *r_ent, double *r_chisq, double *r_mean,
                     double *r_montepicalc, double *r_scc)
	{
	state.end(r_ent, r_chisq, r_mean, r_montepicalc, r_scc);
	return true;
	}

BloomFilterVal::BloomFilterVal()
	: OpaqueVal(bloomfilter_type)
	{
	type = 0;
	hash = 0;
	bloom_filter = 0;
	}

BloomFilterVal::BloomFilterVal(OpaqueType* t)
	: OpaqueVal(t)
	{
	type = 0;
	hash = 0;
	bloom_filter = 0;
	}

BloomFilterVal::BloomFilterVal(probabilistic::BloomFilter* bf)
	: OpaqueVal(bloomfilter_type)
	{
	type = 0;
	hash = 0;
	bloom_filter = bf;
	}

Val* BloomFilterVal::DoClone(CloneState* state)
	{
	if ( bloom_filter )
		{
		auto bf = new BloomFilterVal(bloom_filter->Clone());
		bf->Typify(type);
		return bf;
		}

	return new BloomFilterVal();
	}

bool BloomFilterVal::Typify(BroType* arg_type)
	{
	if ( type )
		return false;

	type = arg_type;
	type->Ref();

	TypeList* tl = new TypeList(type);
	tl->Append(type->Ref());
	hash = new CompositeHash(tl);
	Unref(tl);

	return true;
	}

BroType* BloomFilterVal::Type() const
	{
	return type;
	}

void BloomFilterVal::Add(const Val* val)
	{
	HashKey* key = hash->ComputeHash(val, 1);
	bloom_filter->Add(key);
	delete key;
	}

size_t BloomFilterVal::Count(const Val* val) const
	{
	HashKey* key = hash->ComputeHash(val, 1);
	size_t cnt = bloom_filter->Count(key);
	delete key;
	return cnt;
	}

void BloomFilterVal::Clear()
	{
	bloom_filter->Clear();
	}

bool BloomFilterVal::Empty() const
	{
	return bloom_filter->Empty();
	}

string BloomFilterVal::InternalState() const
	{
	return bloom_filter->InternalState();
	}

BloomFilterVal* BloomFilterVal::Merge(const BloomFilterVal* x,
				      const BloomFilterVal* y)
	{
	if ( x->Type() && // any one 0 is ok here
	     y->Type() &&
	     ! same_type(x->Type(), y->Type()) )
		{
		reporter->Error("cannot merge Bloom filters with different types");
		return 0;
		}

	if ( typeid(*x->bloom_filter) != typeid(*y->bloom_filter) )
		{
		reporter->Error("cannot merge different Bloom filter types");
		return 0;
		}

	probabilistic::BloomFilter* copy = x->bloom_filter->Clone();

	if ( ! copy->Merge(y->bloom_filter) )
		{
		reporter->Error("failed to merge Bloom filter");
		return 0;
		}

	BloomFilterVal* merged = new BloomFilterVal(copy);

	if ( x->Type() && ! merged->Typify(x->Type()) )
		{
		reporter->Error("failed to set type on merged Bloom filter");
		return 0;
		}

	return merged;
	}

BloomFilterVal::~BloomFilterVal()
	{
	Unref(type);
	delete hash;
	delete bloom_filter;
	}

CardinalityVal::CardinalityVal() : OpaqueVal(cardinality_type)
	{
	c = 0;
	type = 0;
	hash = 0;
	}

CardinalityVal::CardinalityVal(probabilistic::CardinalityCounter* arg_c)
	: OpaqueVal(cardinality_type)
	{
	c = arg_c;
	type = 0;
	hash = 0;
	}

CardinalityVal::~CardinalityVal()
	{
	Unref(type);
	delete c;
	delete hash;
	}

Val* CardinalityVal::DoClone(CloneState* state)
	{
	return new CardinalityVal(new probabilistic::CardinalityCounter(*c));
	}

bool CardinalityVal::Typify(BroType* arg_type)
	{
	if ( type )
		return false;

	type = arg_type;
	type->Ref();

	TypeList* tl = new TypeList(type);
	tl->Append(type->Ref());
	hash = new CompositeHash(tl);
	Unref(tl);

	return true;
	}

BroType* CardinalityVal::Type() const
	{
	return type;
	}

void CardinalityVal::Add(const Val* val)
	{
	HashKey* key = hash->ComputeHash(val, 1);
	c->AddElement(key->Hash());
	delete key;
	}
