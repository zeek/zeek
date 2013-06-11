#include "OpaqueVal.h"

#include "BloomFilter.h"
#include "NetVar.h"
#include "Reporter.h"
#include "Serializer.h"

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
		return new StringVal("");

	StringVal* result = DoGet();
	valid = false;
	return result;
	}

bool HashVal::Feed(const void* data, size_t size)
	{
	if ( valid )
		return DoFeed(data, size);

	reporter->InternalError("invalid opaque hash value");
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
	return new StringVal("");
	}

HashVal::HashVal(OpaqueType* t) : OpaqueVal(t)
	{
	valid = false;
	}

IMPLEMENT_SERIAL(HashVal, SER_HASH_VAL);

bool HashVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_HASH_VAL, OpaqueVal);
	return SERIALIZE(valid);
	}

bool HashVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);
	return UNSERIALIZE(&valid);
	}

MD5Val::MD5Val() : HashVal(md5_type)
	{
	}

void MD5Val::digest(val_list& vlist, u_char result[MD5_DIGEST_LENGTH])
	{
	MD5_CTX h;
	md5_init(&h);

	loop_over_list(vlist, i)
		{
		Val* v = vlist[i];
		if ( v->Type()->Tag() == TYPE_STRING )
			{
			const BroString* str = v->AsString();
			md5_update(&h, str->Bytes(), str->Len());
			}
		else
			{
			ODesc d(DESC_BINARY);
			v->Describe(&d);
			md5_update(&h, (const u_char *) d.Bytes(), d.Len());
			}
		}

	md5_final(&h, result);
	}

void MD5Val::hmac(val_list& vlist,
                  u_char key[MD5_DIGEST_LENGTH],
                  u_char result[MD5_DIGEST_LENGTH])
	{
	digest(vlist, result);
	for ( int i = 0; i < MD5_DIGEST_LENGTH; ++i )
		result[i] ^= key[i];

	MD5(result, MD5_DIGEST_LENGTH, result);
	}

bool MD5Val::DoInit()
	{
	assert(! IsValid());
	md5_init(&ctx);
	return true;
	}

bool MD5Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	md5_update(&ctx, data, size);
	return true;
	}

StringVal* MD5Val::DoGet()
	{
	if ( ! IsValid() )
		return new StringVal("");

	u_char digest[MD5_DIGEST_LENGTH];
	md5_final(&ctx, digest);
	return new StringVal(md5_digest_print(digest));
	}

IMPLEMENT_SERIAL(MD5Val, SER_MD5_VAL);

bool MD5Val::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_MD5_VAL, HashVal);

	if ( ! IsValid() )
		return true;

	if ( ! (SERIALIZE(ctx.A) &&
		SERIALIZE(ctx.B) &&
		SERIALIZE(ctx.C) &&
		SERIALIZE(ctx.D) &&
		SERIALIZE(ctx.Nl) &&
		SERIALIZE(ctx.Nh)) )
		return false;

	for ( int i = 0; i < MD5_LBLOCK; ++i )
		{
		if ( ! SERIALIZE(ctx.data[i]) )
			return false;
		}

	if ( ! SERIALIZE(ctx.num) )
		return false;

	return true;
	}

bool MD5Val::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(HashVal);

	if ( ! IsValid() )
		return true;

	if ( ! (UNSERIALIZE(&ctx.A) &&
		UNSERIALIZE(&ctx.B) &&
		UNSERIALIZE(&ctx.C) &&
		UNSERIALIZE(&ctx.D) &&
		UNSERIALIZE(&ctx.Nl) &&
		UNSERIALIZE(&ctx.Nh)) )
		return false;

	for ( int i = 0; i < MD5_LBLOCK; ++i )
		{
		if ( ! UNSERIALIZE(&ctx.data[i]) )
			return false;
		}

	if ( ! UNSERIALIZE(&ctx.num) )
		return false;

	return true;
	}

SHA1Val::SHA1Val() : HashVal(sha1_type)
	{
	}

void SHA1Val::digest(val_list& vlist, u_char result[SHA_DIGEST_LENGTH])
	{
	SHA_CTX h;
	sha1_init(&h);

	loop_over_list(vlist, i)
		{
		Val* v = vlist[i];
		if ( v->Type()->Tag() == TYPE_STRING )
			{
			const BroString* str = v->AsString();
			sha1_update(&h, str->Bytes(), str->Len());
			}
		else
			{
			ODesc d(DESC_BINARY);
			v->Describe(&d);
			sha1_update(&h, (const u_char *) d.Bytes(), d.Len());
			}
		}

	sha1_final(&h, result);
	}

bool SHA1Val::DoInit()
	{
	assert(! IsValid());
	sha1_init(&ctx);
	return true;
	}

bool SHA1Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	sha1_update(&ctx, data, size);
	return true;
	}

StringVal* SHA1Val::DoGet()
	{
	if ( ! IsValid() )
		return new StringVal("");

	u_char digest[SHA_DIGEST_LENGTH];
	sha1_final(&ctx, digest);
	return new StringVal(sha1_digest_print(digest));
	}

IMPLEMENT_SERIAL(SHA1Val, SER_SHA1_VAL);

bool SHA1Val::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SHA1_VAL, HashVal);

	if ( ! IsValid() )
		return true;

	if ( ! (SERIALIZE(ctx.h0) &&
		SERIALIZE(ctx.h1) &&
		SERIALIZE(ctx.h2) &&
		SERIALIZE(ctx.h3) &&
		SERIALIZE(ctx.h4) &&
		SERIALIZE(ctx.Nl) &&
		SERIALIZE(ctx.Nh)) )
		return false;

	for ( int i = 0; i < SHA_LBLOCK; ++i )
		{
		if ( ! SERIALIZE(ctx.data[i]) )
			return false;
		}

	if ( ! SERIALIZE(ctx.num) )
		return false;

	return true;
	}

bool SHA1Val::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(HashVal);

	if ( ! IsValid() )
		return true;

	if ( ! (UNSERIALIZE(&ctx.h0) &&
		UNSERIALIZE(&ctx.h1) &&
		UNSERIALIZE(&ctx.h2) &&
		UNSERIALIZE(&ctx.h3) &&
		UNSERIALIZE(&ctx.h4) &&
		UNSERIALIZE(&ctx.Nl) &&
		UNSERIALIZE(&ctx.Nh)) )
		return false;

	for ( int i = 0; i < SHA_LBLOCK; ++i )
		{
		if ( ! UNSERIALIZE(&ctx.data[i]) )
			return false;
		}

	if ( ! UNSERIALIZE(&ctx.num) )
		return false;

	return true;
	}

SHA256Val::SHA256Val() : HashVal(sha256_type)
	{
	}

void SHA256Val::digest(val_list& vlist, u_char result[SHA256_DIGEST_LENGTH])
	{
	SHA256_CTX h;
	sha256_init(&h);

	loop_over_list(vlist, i)
		{
		Val* v = vlist[i];
		if ( v->Type()->Tag() == TYPE_STRING )
			{
			const BroString* str = v->AsString();
			sha256_update(&h, str->Bytes(), str->Len());
			}
		else
			{
			ODesc d(DESC_BINARY);
			v->Describe(&d);
			sha256_update(&h, (const u_char *) d.Bytes(), d.Len());
			}
		}

	sha256_final(&h, result);
	}

bool SHA256Val::DoInit()
	{
	assert( ! IsValid() );
	sha256_init(&ctx);
	return true;
	}

bool SHA256Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	sha256_update(&ctx, data, size);
	return true;
	}

StringVal* SHA256Val::DoGet()
	{
	if ( ! IsValid() )
		return new StringVal("");

	u_char digest[SHA256_DIGEST_LENGTH];
	sha256_final(&ctx, digest);
	return new StringVal(sha256_digest_print(digest));
	}

IMPLEMENT_SERIAL(SHA256Val, SER_SHA256_VAL);

bool SHA256Val::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SHA256_VAL, HashVal);

	if ( ! IsValid() )
		return true;

	for ( int i = 0; i < 8; ++i )
		{
		if ( ! SERIALIZE(ctx.h[i]) )
			return false;
		}

	if ( ! (SERIALIZE(ctx.Nl) &&
		SERIALIZE(ctx.Nh)) )
		return false;

	for ( int i = 0; i < SHA_LBLOCK; ++i )
		{
		if ( ! SERIALIZE(ctx.data[i]) )
			return false;
		}

	if ( ! (SERIALIZE(ctx.num) &&
		SERIALIZE(ctx.md_len)) )
	     return false;

	return true;
	}

bool SHA256Val::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(HashVal);

	if ( ! IsValid() )
		return true;

	for ( int i = 0; i < 8; ++i )
		{
		if ( ! UNSERIALIZE(&ctx.h[i]) )
			return false;
		}

	if ( ! (UNSERIALIZE(&ctx.Nl) &&
		UNSERIALIZE(&ctx.Nh)) )
	     return false;

	for ( int i = 0; i < SHA_LBLOCK; ++i )
		{
		if ( ! UNSERIALIZE(&ctx.data[i]) )
			return false;
		}


	if ( ! (UNSERIALIZE(&ctx.num) &&
		UNSERIALIZE(&ctx.md_len)) )
		return false;

	return true;
	}

EntropyVal::EntropyVal() : OpaqueVal(entropy_type)
	{
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

IMPLEMENT_SERIAL(EntropyVal, SER_ENTROPY_VAL);

bool EntropyVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ENTROPY_VAL, OpaqueVal);

	for ( int i = 0; i < 256; ++i )
		{
		if ( ! SERIALIZE(state.ccount[i]) )
			return false;
		}

	if ( ! (SERIALIZE(state.totalc) &&
		SERIALIZE(state.mp) &&
		SERIALIZE(state.sccfirst)) )
		return false;

	for ( int i = 0; i < RT_MONTEN; ++i )
		{
		if ( ! SERIALIZE(state.monte[i]) )
			return false;
		}

	if ( ! (SERIALIZE(state.inmont) &&
		SERIALIZE(state.mcount) &&
		SERIALIZE(state.cexp) &&
		SERIALIZE(state.montex) &&
		SERIALIZE(state.montey) &&
		SERIALIZE(state.montepi) &&
		SERIALIZE(state.sccu0) &&
		SERIALIZE(state.scclast) &&
		SERIALIZE(state.scct1) &&
		SERIALIZE(state.scct2) &&
		SERIALIZE(state.scct3)) )
		return false;

	return true;
	}

bool EntropyVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);

	for ( int i = 0; i < 256; ++i )
		{
		if ( ! UNSERIALIZE(&state.ccount[i]) )
			return false;
		}

	if ( ! (UNSERIALIZE(&state.totalc) &&
		UNSERIALIZE(&state.mp) &&
		UNSERIALIZE(&state.sccfirst)) )
		return false;

	for ( int i = 0; i < RT_MONTEN; ++i )
		{
		if ( ! UNSERIALIZE(&state.monte[i]) )
			return false;
		}

	if ( ! (UNSERIALIZE(&state.inmont) &&
		UNSERIALIZE(&state.mcount) &&
		UNSERIALIZE(&state.cexp) &&
		UNSERIALIZE(&state.montex) &&
		UNSERIALIZE(&state.montey) &&
		UNSERIALIZE(&state.montepi) &&
		UNSERIALIZE(&state.sccu0) &&
		UNSERIALIZE(&state.scclast) &&
		UNSERIALIZE(&state.scct1) &&
		UNSERIALIZE(&state.scct2) &&
		UNSERIALIZE(&state.scct3)) )
		return false;

	return true;
	}

BloomFilterVal::BloomFilterVal()
  : OpaqueVal(bloomfilter_type),
    type_(NULL),
    hash_(NULL),
    bloom_filter_(NULL)
	{
	}

BloomFilterVal::BloomFilterVal(OpaqueType* t)
  : OpaqueVal(t),
    type_(NULL),
    hash_(NULL),
    bloom_filter_(NULL)
	{
	}

BloomFilterVal::BloomFilterVal(BloomFilter* bf)
  : OpaqueVal(bloomfilter_type),
    type_(NULL),
    hash_(NULL),
    bloom_filter_(bf)
	{
	}

bool BloomFilterVal::Typify(BroType* type)
  {
  if ( type_ )
    return false;
  type_ = type;
  type_->Ref();
  TypeList* tl = new TypeList(type_);
  tl->Append(type_);
  hash_ = new CompositeHash(tl);
  Unref(tl);
  return true;
  }

BroType* BloomFilterVal::Type() const
  {
  return type_;
  }

void BloomFilterVal::Add(const Val* val)
  {
  HashKey* key = hash_->ComputeHash(val, 1);
  bloom_filter_->Add(key->Hash());
  }

size_t BloomFilterVal::Count(const Val* val) const
  {
  HashKey* key = hash_->ComputeHash(val, 1);
  return bloom_filter_->Count(key->Hash());
  }

BloomFilterVal* BloomFilterVal::Merge(const BloomFilterVal* x,
                                      const BloomFilterVal* y)
  {
  if ( x->Type() != y->Type() )
    {
    reporter->InternalError("cannot merge Bloom filters with different types");
    return NULL;
    }

  BloomFilterVal* result;
  if ( (result = DoMerge<BasicBloomFilter>(x, y)) )
    return result;
  else if ( (result = DoMerge<CountingBloomFilter>(x, y)) )
    return result;

  return NULL;
  }

BloomFilterVal::~BloomFilterVal()
  {
  if ( type_ )
    Unref(type_);
  if ( hash_ )
    delete hash_;
  if ( bloom_filter_ )
    delete bloom_filter_;
  }

IMPLEMENT_SERIAL(BloomFilterVal, SER_BLOOMFILTER_VAL);

bool BloomFilterVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BLOOMFILTER_VAL, OpaqueVal);
	if ( ! type_->Serialize(info) )
	  return false;
	return bloom_filter_->Serialize(info);
  }

bool BloomFilterVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);

	type_ = BroType::Unserialize(info);
	if ( ! type_ )
	  return false;
  TypeList* tl = new TypeList(type_);
  tl->Append(type_);
  hash_ = new CompositeHash(tl);
  Unref(tl);

	bloom_filter_ = BloomFilter::Unserialize(info);
	return bloom_filter_ != NULL;
  }
