// See the file "COPYING" in the main distribution directory for copyright.

#include "OpaqueVal.h"
#include "NetVar.h"
#include "Reporter.h"
#include "Serializer.h"
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
		return new StringVal("");

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

IMPLEMENT_SERIAL(BloomFilterVal, SER_BLOOMFILTER_VAL);

bool BloomFilterVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BLOOMFILTER_VAL, OpaqueVal);

	bool is_typed = (type != 0);

	if ( ! SERIALIZE(is_typed) )
		return false;

	if ( is_typed && ! type->Serialize(info) )
		return false;

	return bloom_filter->Serialize(info);
	}

bool BloomFilterVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);

	bool is_typed;
	if ( ! UNSERIALIZE(&is_typed) )
		return false;

	if ( is_typed )
		{
		BroType* t = BroType::Unserialize(info);
		if ( ! Typify(t) )
			return false;

		Unref(t);
		}

	bloom_filter = probabilistic::BloomFilter::Unserialize(info);
	return bloom_filter != 0;
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

IMPLEMENT_SERIAL(CardinalityVal, SER_CARDINALITY_VAL);

bool CardinalityVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_CARDINALITY_VAL, OpaqueVal);

	bool valid = true;
	bool is_typed = (type != 0);

	valid &= SERIALIZE(is_typed);

	if ( is_typed )
		valid &= type->Serialize(info);

	return c->Serialize(info);
	}

bool CardinalityVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);

	bool is_typed;
	if ( ! UNSERIALIZE(&is_typed) )
		return false;

	if ( is_typed )
		{
		BroType* t = BroType::Unserialize(info);
		if ( ! Typify(t) )
			return false;

		Unref(t);
		}

	c = probabilistic::CardinalityCounter::Unserialize(info);
	return c != 0;
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

