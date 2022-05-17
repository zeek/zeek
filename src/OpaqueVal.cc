// See the file "COPYING" in the main distribution directory for copyright.

// When using OpenSSL 3, we use deprecated APIs for MD5, SHA1 and SHA256. The reason is that, as of
// OpenSSL 3.0, there is no API anymore that lets you store the internal state of hashing functions.
// For more information, see https://github.com/zeek/zeek/issues/1379 and
// https://github.com/openssl/openssl/issues/14222 Since I don't feel like getting warnings every
// time we compile this file - let's silence them.

#define OPENSSL_SUPPRESS_DEPRECATED

#include "zeek/OpaqueVal.h"

#include <broker/data.hh>
#include <broker/error.hh>
#include <memory>

#include "zeek/CompHash.h"
#include "zeek/Desc.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Var.h"
#include "zeek/probabilistic/BloomFilter.h"
#include "zeek/probabilistic/CardinalityCounter.h"

namespace zeek
	{

// Helper to retrieve a broker value out of a broker::vector at a specified
// index, and casted to the expected destination type.
template <typename S, typename V, typename D>
inline bool get_vector_idx(const V& v, unsigned int i, D* dst)
	{
	if ( i >= v.size() )
		return false;

	auto x = broker::get_if<S>(&v[i]);
	if ( ! x )
		return false;

	*dst = static_cast<D>(*x);
	return true;
	}

OpaqueMgr* OpaqueMgr::mgr()
	{
	static OpaqueMgr mgr;
	return &mgr;
	}

OpaqueVal::OpaqueVal(OpaqueTypePtr t) : Val(std::move(t)) { }

OpaqueVal::~OpaqueVal() { }

const std::string& OpaqueMgr::TypeID(const OpaqueVal* v) const
	{
	auto x = _types.find(v->OpaqueName());

	if ( x == _types.end() )
		reporter->InternalError("OpaqueMgr::TypeID: opaque type %s not registered",
		                        v->OpaqueName());

	return x->first;
	}

OpaqueValPtr OpaqueMgr::Instantiate(const std::string& id) const
	{
	auto x = _types.find(id);
	return x != _types.end() ? (*x->second)() : nullptr;
	}

broker::expected<broker::data> OpaqueVal::Serialize() const
	{
	auto type = OpaqueMgr::mgr()->TypeID(this);

	auto d = DoSerialize();
	if ( ! d )
		return d.error();

	return {broker::vector{std::move(type), std::move(*d)}};
	}

OpaqueValPtr OpaqueVal::Unserialize(const broker::data& data)
	{
	auto v = broker::get_if<broker::vector>(&data);

	if ( ! (v && v->size() == 2) )
		return nullptr;

	auto type = broker::get_if<std::string>(&(*v)[0]);
	if ( ! type )
		return nullptr;

	auto val = OpaqueMgr::mgr()->Instantiate(*type);
	if ( ! val )
		return nullptr;

	if ( ! val->DoUnserialize((*v)[1]) )
		return nullptr;

	return val;
	}

broker::expected<broker::data> OpaqueVal::SerializeType(const TypePtr& t)
	{
	if ( t->InternalType() == TYPE_INTERNAL_ERROR )
		return broker::ec::invalid_data;

	if ( t->InternalType() == TYPE_INTERNAL_OTHER )
		{
		// Serialize by name.
		assert(t->GetName().size());
		return {broker::vector{true, t->GetName()}};
		}

	// A base type.
	return {broker::vector{false, static_cast<uint64_t>(t->Tag())}};
	}

TypePtr OpaqueVal::UnserializeType(const broker::data& data)
	{
	auto v = broker::get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return nullptr;

	auto by_name = broker::get_if<bool>(&(*v)[0]);
	if ( ! by_name )
		return nullptr;

	if ( *by_name )
		{
		auto name = broker::get_if<std::string>(&(*v)[1]);
		if ( ! name )
			return nullptr;

		const auto& id = detail::global_scope()->Find(*name);
		if ( ! id )
			return nullptr;

		if ( ! id->IsType() )
			return nullptr;

		return id->GetType();
		}

	auto tag = broker::get_if<uint64_t>(&(*v)[1]);
	if ( ! tag )
		return nullptr;

	return base_type(static_cast<TypeTag>(*tag));
	}

ValPtr OpaqueVal::DoClone(CloneState* state)
	{
	auto d = OpaqueVal::Serialize();
	if ( ! d )
		return nullptr;

	auto rval = OpaqueVal::Unserialize(std::move(*d));
	return state->NewClone(this, std::move(rval));
	}

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

StringValPtr HashVal::Get()
	{
	if ( ! valid )
		return val_mgr->EmptyString();

	auto result = DoGet();
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

StringValPtr HashVal::DoGet()
	{
	assert(! "missing implementation of DoGet()");
	return val_mgr->EmptyString();
	}

HashVal::HashVal(OpaqueTypePtr t) : OpaqueVal(std::move(t))
	{
	valid = false;
	}

MD5Val::MD5Val() : HashVal(md5_type)
	{
	memset(&ctx, 0, sizeof(ctx));
	}

MD5Val::~MD5Val()
	{
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
#endif
	}

void HashVal::digest_one(EVP_MD_CTX* h, const Val* v)
	{
	if ( v->GetType()->Tag() == TYPE_STRING )
		{
		const String* str = v->AsString();
		detail::hash_update(h, str->Bytes(), str->Len());
		}
	else
		{
		ODesc d(DESC_BINARY);
		v->Describe(&d);
		detail::hash_update(h, (const u_char*)d.Bytes(), d.Len());
		}
	}

void HashVal::digest_one(EVP_MD_CTX* h, const ValPtr& v)
	{
	digest_one(h, v.get());
	}

ValPtr MD5Val::DoClone(CloneState* state)
	{
	auto out = make_intrusive<MD5Val>();

	if ( IsValid() )
		{
		if ( ! out->Init() )
			return nullptr;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_copy_ex(out->ctx, ctx);
#else
		out->ctx = ctx;
#endif
		}

	return state->NewClone(this, std::move(out));
	}

bool MD5Val::DoInit()
	{
	assert(! IsValid());
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	ctx = detail::hash_init(detail::Hash_MD5);
#else
	MD5_Init(&ctx);
#endif
	return true;
	}

bool MD5Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	detail::hash_update(ctx, data, size);
#else
	MD5_Update(&ctx, data, size);
#endif
	return true;
	}

StringValPtr MD5Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->EmptyString();

	u_char digest[MD5_DIGEST_LENGTH];
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	detail::hash_final(ctx, digest);
#else
	MD5_Final(digest, &ctx);
#endif
	return make_intrusive<StringVal>(detail::md5_digest_print(digest));
	}

IMPLEMENT_OPAQUE_VALUE(MD5Val)

broker::expected<broker::data> MD5Val::DoSerialize() const
	{
	if ( ! IsValid() )
		return {broker::vector{false}};

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	MD5_CTX* md = (MD5_CTX*)EVP_MD_CTX_md_data(ctx);
	auto data = std::string(reinterpret_cast<const char*>(md), sizeof(MD5_CTX));
#else
	auto data = std::string(reinterpret_cast<const char*>(&ctx), sizeof(ctx));
#endif

	broker::vector d = {true, data};
	return {std::move(d)};
	}

bool MD5Val::DoUnserialize(const broker::data& data)
	{
	auto d = broker::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	auto valid = broker::get_if<bool>(&(*d)[0]);
	if ( ! valid )
		return false;

	if ( ! *valid )
		{
		assert(! IsValid()); // default set by ctor
		return true;
		}

	if ( (*d).size() != 2 )
		return false;

	auto s = broker::get_if<std::string>(&(*d)[1]);
	if ( ! s )
		return false;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	if ( sizeof(MD5_CTX) != s->size() )
#else
	if ( sizeof(ctx) != s->size() )
#endif
		return false;

	Init();
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	MD5_CTX* md = (MD5_CTX*)EVP_MD_CTX_md_data(ctx);
	memcpy(md, s->data(), s->size());
#else
	memcpy(&ctx, s->data(), s->size());
#endif
	return true;
	}

SHA1Val::SHA1Val() : HashVal(sha1_type)
	{
	memset(&ctx, 0, sizeof(ctx));
	}

SHA1Val::~SHA1Val()
	{
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
#endif
	}

ValPtr SHA1Val::DoClone(CloneState* state)
	{
	auto out = make_intrusive<SHA1Val>();

	if ( IsValid() )
		{
		if ( ! out->Init() )
			return nullptr;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_copy_ex(out->ctx, ctx);
#else
		out->ctx = ctx;
#endif
		}

	return state->NewClone(this, std::move(out));
	}

bool SHA1Val::DoInit()
	{
	assert(! IsValid());
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	ctx = detail::hash_init(detail::Hash_SHA1);
#else
	SHA1_Init(&ctx);
#endif
	return true;
	}

bool SHA1Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	detail::hash_update(ctx, data, size);
#else
	SHA1_Update(&ctx, data, size);
#endif
	return true;
	}

StringValPtr SHA1Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->EmptyString();

	u_char digest[SHA_DIGEST_LENGTH];
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	detail::hash_final(ctx, digest);
#else
	SHA1_Final(digest, &ctx);
#endif
	return make_intrusive<StringVal>(detail::sha1_digest_print(digest));
	}

IMPLEMENT_OPAQUE_VALUE(SHA1Val)

broker::expected<broker::data> SHA1Val::DoSerialize() const
	{
	if ( ! IsValid() )
		return {broker::vector{false}};

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	SHA_CTX* md = (SHA_CTX*)EVP_MD_CTX_md_data(ctx);
	auto data = std::string(reinterpret_cast<const char*>(md), sizeof(SHA_CTX));
#else
	auto data = std::string(reinterpret_cast<const char*>(&ctx), sizeof(ctx));
#endif

	broker::vector d = {true, data};

	return {std::move(d)};
	}

bool SHA1Val::DoUnserialize(const broker::data& data)
	{
	auto d = broker::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	auto valid = broker::get_if<bool>(&(*d)[0]);
	if ( ! valid )
		return false;

	if ( ! *valid )
		{
		assert(! IsValid()); // default set by ctor
		return true;
		}

	if ( (*d).size() != 2 )
		return false;

	auto s = broker::get_if<std::string>(&(*d)[1]);
	if ( ! s )
		return false;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	if ( sizeof(SHA_CTX) != s->size() )
#else
	if ( sizeof(ctx) != s->size() )
#endif
		return false;

	Init();
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	SHA_CTX* md = (SHA_CTX*)EVP_MD_CTX_md_data(ctx);
	memcpy(md, s->data(), s->size());
#else
	memcpy(&ctx, s->data(), s->size());
#endif
	return true;
	}

SHA256Val::SHA256Val() : HashVal(sha256_type)
	{
	memset(&ctx, 0, sizeof(ctx));
	}

SHA256Val::~SHA256Val()
	{
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
#endif
	}

ValPtr SHA256Val::DoClone(CloneState* state)
	{
	auto out = make_intrusive<SHA256Val>();

	if ( IsValid() )
		{
		if ( ! out->Init() )
			return nullptr;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
		EVP_MD_CTX_copy_ex(out->ctx, ctx);
#else
		out->ctx = ctx;
#endif
		}

	return state->NewClone(this, std::move(out));
	}

bool SHA256Val::DoInit()
	{
	assert(! IsValid());
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	ctx = detail::hash_init(detail::Hash_SHA256);
#else
	SHA256_Init(&ctx);
#endif
	return true;
	}

bool SHA256Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	detail::hash_update(ctx, data, size);
#else
	SHA256_Update(&ctx, data, size);
#endif
	return true;
	}

StringValPtr SHA256Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->EmptyString();

	u_char digest[SHA256_DIGEST_LENGTH];
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	detail::hash_final(ctx, digest);
#else
	SHA256_Final(digest, &ctx);
#endif
	return make_intrusive<StringVal>(detail::sha256_digest_print(digest));
	}

IMPLEMENT_OPAQUE_VALUE(SHA256Val)

broker::expected<broker::data> SHA256Val::DoSerialize() const
	{
	if ( ! IsValid() )
		return {broker::vector{false}};

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	SHA256_CTX* md = (SHA256_CTX*)EVP_MD_CTX_md_data(ctx);
	auto data = std::string(reinterpret_cast<const char*>(md), sizeof(SHA256_CTX));
#else
	auto data = std::string(reinterpret_cast<const char*>(&ctx), sizeof(ctx));
#endif

	broker::vector d = {true, data};

	return {std::move(d)};
	}

bool SHA256Val::DoUnserialize(const broker::data& data)
	{
	auto d = broker::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	auto valid = broker::get_if<bool>(&(*d)[0]);
	if ( ! valid )
		return false;

	if ( ! *valid )
		{
		assert(! IsValid()); // default set by ctor
		return true;
		}

	if ( (*d).size() != 2 )
		return false;

	auto s = broker::get_if<std::string>(&(*d)[1]);
	if ( ! s )
		return false;

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	if ( sizeof(SHA256_CTX) != s->size() )
#else
	if ( sizeof(ctx) != s->size() )
#endif
		return false;

	Init();
#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
	SHA256_CTX* md = (SHA256_CTX*)EVP_MD_CTX_md_data(ctx);
	memcpy(md, s->data(), s->size());
#else
	memcpy(&ctx, s->data(), s->size());
#endif
	return true;
	}

EntropyVal::EntropyVal() : OpaqueVal(entropy_type) { }

bool EntropyVal::Feed(const void* data, size_t size)
	{
	state.add(data, size);
	return true;
	}

bool EntropyVal::Get(double* r_ent, double* r_chisq, double* r_mean, double* r_montepicalc,
                     double* r_scc)
	{
	state.end(r_ent, r_chisq, r_mean, r_montepicalc, r_scc);
	return true;
	}

IMPLEMENT_OPAQUE_VALUE(EntropyVal)

broker::expected<broker::data> EntropyVal::DoSerialize() const
	{
	broker::vector d = {
		static_cast<uint64_t>(state.totalc),   static_cast<uint64_t>(state.mp),
		static_cast<uint64_t>(state.sccfirst), static_cast<uint64_t>(state.inmont),
		static_cast<uint64_t>(state.mcount),   static_cast<uint64_t>(state.cexp),
		static_cast<uint64_t>(state.montex),   static_cast<uint64_t>(state.montey),
		static_cast<uint64_t>(state.montepi),  static_cast<uint64_t>(state.sccu0),
		static_cast<uint64_t>(state.scclast),  static_cast<uint64_t>(state.scct1),
		static_cast<uint64_t>(state.scct2),    static_cast<uint64_t>(state.scct3),
	};

	d.reserve(256 + 3 + RT_MONTEN + 11);

	for ( int i = 0; i < 256; ++i )
		d.emplace_back(static_cast<uint64_t>(state.ccount[i]));

	for ( int i = 0; i < RT_MONTEN; ++i )
		d.emplace_back(static_cast<uint64_t>(state.monte[i]));

	return {std::move(d)};
	}

bool EntropyVal::DoUnserialize(const broker::data& data)
	{
	auto d = broker::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	if ( ! get_vector_idx<uint64_t>(*d, 0, &state.totalc) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 1, &state.mp) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 2, &state.sccfirst) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 3, &state.inmont) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 4, &state.mcount) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 5, &state.cexp) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 6, &state.montex) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 7, &state.montey) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 8, &state.montepi) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 9, &state.sccu0) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 10, &state.scclast) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 11, &state.scct1) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 12, &state.scct2) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 13, &state.scct3) )
		return false;

	for ( int i = 0; i < 256; ++i )
		{
		if ( ! get_vector_idx<uint64_t>(*d, 14 + i, &state.ccount[i]) )
			return false;
		}

	for ( int i = 0; i < RT_MONTEN; ++i )
		{
		if ( ! get_vector_idx<uint64_t>(*d, 14 + 256 + i, &state.monte[i]) )
			return false;
		}

	return true;
	}

BloomFilterVal::BloomFilterVal() : OpaqueVal(bloomfilter_type)
	{
	hash = nullptr;
	bloom_filter = nullptr;
	}

BloomFilterVal::BloomFilterVal(probabilistic::BloomFilter* bf) : OpaqueVal(bloomfilter_type)
	{
	hash = nullptr;
	bloom_filter = bf;
	}

ValPtr BloomFilterVal::DoClone(CloneState* state)
	{
	if ( bloom_filter )
		{
		auto bf = make_intrusive<BloomFilterVal>(bloom_filter->Clone());
		assert(type);
		bf->Typify(type);
		return state->NewClone(this, std::move(bf));
		}

	return state->NewClone(this, make_intrusive<BloomFilterVal>());
	}

bool BloomFilterVal::Typify(TypePtr arg_type)
	{
	if ( type )
		return false;

	type = std::move(arg_type);

	auto tl = make_intrusive<TypeList>(type);
	tl->Append(type);
	hash = new detail::CompositeHash(std::move(tl));

	return true;
	}

void BloomFilterVal::Add(const Val* val)
	{
	auto key = hash->MakeHashKey(*val, true);
	bloom_filter->Add(key.get());
	}

bool BloomFilterVal::Decrement(const Val* val)
	{
	auto key = hash->MakeHashKey(*val, true);
	return bloom_filter->Decrement(key.get());
	}

size_t BloomFilterVal::Count(const Val* val) const
	{
	auto key = hash->MakeHashKey(*val, true);
	size_t cnt = bloom_filter->Count(key.get());
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

std::string BloomFilterVal::InternalState() const
	{
	return bloom_filter->InternalState();
	}

BloomFilterValPtr BloomFilterVal::Merge(const BloomFilterVal* x, const BloomFilterVal* y)
	{
	if ( x->Type() && // any one 0 is ok here
	     y->Type() && ! same_type(x->Type(), y->Type()) )
		{
		reporter->Error("cannot merge Bloom filters with different types");
		return nullptr;
		}

	auto final_type = x->Type() ? x->Type() : y->Type();

	if ( typeid(*x->bloom_filter) != typeid(*y->bloom_filter) )
		{
		reporter->Error("cannot merge different Bloom filter types");
		return nullptr;
		}

	probabilistic::BloomFilter* copy = x->bloom_filter->Clone();

	if ( ! copy->Merge(y->bloom_filter) )
		{
		delete copy;
		reporter->Error("failed to merge Bloom filter");
		return nullptr;
		}

	auto merged = make_intrusive<BloomFilterVal>(copy);

	if ( final_type && ! merged->Typify(final_type) )
		{
		reporter->Error("failed to set type on merged Bloom filter");
		return nullptr;
		}

	return merged;
	}

BloomFilterValPtr BloomFilterVal::Intersect(const BloomFilterVal* x, const BloomFilterVal* y)
	{
	if ( x->Type() && // any one 0 is ok here
	     y->Type() && ! same_type(x->Type(), y->Type()) )
		{
		reporter->Error("cannot merge Bloom filters with different types");
		return nullptr;
		}

	if ( typeid(*x->bloom_filter) != typeid(*y->bloom_filter) )
		{
		reporter->Error("cannot intersect different Bloom filter types");
		return nullptr;
		}

	auto intersected_bf = x->bloom_filter->Intersect(y->bloom_filter);

	if ( ! intersected_bf )
		{
		reporter->Error("failed to intersect Bloom filter");
		return nullptr;
		}

	auto final_type = x->Type() ? x->Type() : y->Type();

	auto intersected = make_intrusive<BloomFilterVal>(intersected_bf);

	if ( final_type && ! intersected->Typify(final_type) )
		{
		reporter->Error("Failed to set type on intersected bloom filter");
		return nullptr;
		}

	return intersected;
	}

BloomFilterVal::~BloomFilterVal()
	{
	delete hash;
	delete bloom_filter;
	}

IMPLEMENT_OPAQUE_VALUE(BloomFilterVal)

broker::expected<broker::data> BloomFilterVal::DoSerialize() const
	{
	broker::vector d;

	if ( type )
		{
		auto t = SerializeType(type);
		if ( ! t )
			return broker::ec::invalid_data;

		d.emplace_back(std::move(*t));
		}
	else
		d.emplace_back(broker::none());

	auto bf = bloom_filter->Serialize();
	if ( ! bf )
		return broker::ec::invalid_data; // Cannot serialize;

	d.emplace_back(*bf);
	return {std::move(d)};
	}

bool BloomFilterVal::DoUnserialize(const broker::data& data)
	{
	auto v = broker::get_if<broker::vector>(&data);

	if ( ! (v && v->size() == 2) )
		return false;

	auto no_type = broker::get_if<broker::none>(&(*v)[0]);
	if ( ! no_type )
		{
		auto t = UnserializeType((*v)[0]);

		if ( ! (t && Typify(std::move(t))) )
			return false;
		}

	auto bf = probabilistic::BloomFilter::Unserialize((*v)[1]);
	if ( ! bf )
		return false;

	bloom_filter = bf.release();
	return true;
	}

CardinalityVal::CardinalityVal() : OpaqueVal(cardinality_type)
	{
	c = nullptr;
	hash = nullptr;
	}

CardinalityVal::CardinalityVal(probabilistic::detail::CardinalityCounter* arg_c)
	: OpaqueVal(cardinality_type)
	{
	c = arg_c;
	hash = nullptr;
	}

CardinalityVal::~CardinalityVal()
	{
	delete c;
	delete hash;
	}

ValPtr CardinalityVal::DoClone(CloneState* state)
	{
	return state->NewClone(
		this, make_intrusive<CardinalityVal>(new probabilistic::detail::CardinalityCounter(*c)));
	}

bool CardinalityVal::Typify(TypePtr arg_type)
	{
	if ( type )
		return false;

	type = std::move(arg_type);

	auto tl = make_intrusive<TypeList>(type);
	tl->Append(type);
	hash = new detail::CompositeHash(std::move(tl));

	return true;
	}

void CardinalityVal::Add(const Val* val)
	{
	auto key = hash->MakeHashKey(*val, true);
	c->AddElement(key->Hash());
	}

IMPLEMENT_OPAQUE_VALUE(CardinalityVal)

broker::expected<broker::data> CardinalityVal::DoSerialize() const
	{
	broker::vector d;

	if ( type )
		{
		auto t = SerializeType(type);
		if ( ! t )
			return broker::ec::invalid_data;

		d.emplace_back(std::move(*t));
		}
	else
		d.emplace_back(broker::none());

	auto cs = c->Serialize();
	if ( ! cs )
		return broker::ec::invalid_data;

	d.emplace_back(*cs);
	return {std::move(d)};
	}

bool CardinalityVal::DoUnserialize(const broker::data& data)
	{
	auto v = broker::get_if<broker::vector>(&data);

	if ( ! (v && v->size() == 2) )
		return false;

	auto no_type = broker::get_if<broker::none>(&(*v)[0]);
	if ( ! no_type )
		{
		auto t = UnserializeType((*v)[0]);

		if ( ! (t && Typify(std::move(t))) )
			return false;
		}

	auto cu = probabilistic::detail::CardinalityCounter::Unserialize((*v)[1]);
	if ( ! cu )
		return false;

	c = cu.release();
	return true;
	}

ParaglobVal::ParaglobVal(std::unique_ptr<paraglob::Paraglob> p) : OpaqueVal(paraglob_type)
	{
	this->internal_paraglob = std::move(p);
	}

VectorValPtr ParaglobVal::Get(StringVal*& pattern)
	{
	auto rval = make_intrusive<VectorVal>(id::string_vec);
	std::string string_pattern(reinterpret_cast<const char*>(pattern->Bytes()), pattern->Len());

	std::vector<std::string> matches = this->internal_paraglob->get(string_pattern);
	for ( size_t i = 0; i < matches.size(); i++ )
		rval->Assign(i, make_intrusive<StringVal>(matches.at(i)));

	return rval;
	}

bool ParaglobVal::operator==(const ParaglobVal& other) const
	{
	return *(this->internal_paraglob) == *(other.internal_paraglob);
	}

IMPLEMENT_OPAQUE_VALUE(ParaglobVal)

broker::expected<broker::data> ParaglobVal::DoSerialize() const
	{
	broker::vector d;
	std::unique_ptr<std::vector<uint8_t>> iv = this->internal_paraglob->serialize();
	for ( uint8_t a : *(iv.get()) )
		d.emplace_back(static_cast<uint64_t>(a));
	return {std::move(d)};
	}

bool ParaglobVal::DoUnserialize(const broker::data& data)
	{
	auto d = broker::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	std::unique_ptr<std::vector<uint8_t>> iv(new std::vector<uint8_t>);
	iv->resize(d->size());

	for ( std::vector<broker::data>::size_type i = 0; i < d->size(); ++i )
		{
		if ( ! get_vector_idx<uint64_t>(*d, i, iv.get()->data() + i) )
			return false;
		}

	try
		{
		this->internal_paraglob = std::make_unique<paraglob::Paraglob>(std::move(iv));
		}
	catch ( const paraglob::underflow_error& e )
		{
		reporter->Error("Paraglob underflow error -> %s", e.what());
		return false;
		}
	catch ( const paraglob::overflow_error& e )
		{
		reporter->Error("Paraglob overflow error -> %s", e.what());
		return false;
		}

	return true;
	}

ValPtr ParaglobVal::DoClone(CloneState* state)
	{
	try
		{
		return make_intrusive<ParaglobVal>(
			std::make_unique<paraglob::Paraglob>(this->internal_paraglob->serialize()));
		}
	catch ( const paraglob::underflow_error& e )
		{
		reporter->Error("Paraglob underflow error while cloning -> %s", e.what());
		return nullptr;
		}
	catch ( const paraglob::overflow_error& e )
		{
		reporter->Error("Paraglob overflow error while cloning -> %s", e.what());
		return nullptr;
		}
	}

broker::expected<broker::data> TelemetryVal::DoSerialize() const
	{
	return broker::make_error(broker::ec::invalid_data, "cannot serialize metric handles");
	}

bool TelemetryVal::DoUnserialize(const broker::data&)
	{
	return false;
	}

TelemetryVal::TelemetryVal(telemetry::IntCounter) : OpaqueVal(int_counter_metric_type) { }

TelemetryVal::TelemetryVal(telemetry::IntCounterFamily) : OpaqueVal(int_counter_metric_family_type)
	{
	}

TelemetryVal::TelemetryVal(telemetry::DblCounter) : OpaqueVal(dbl_counter_metric_type) { }

TelemetryVal::TelemetryVal(telemetry::DblCounterFamily) : OpaqueVal(dbl_counter_metric_family_type)
	{
	}

TelemetryVal::TelemetryVal(telemetry::IntGauge) : OpaqueVal(int_gauge_metric_type) { }

TelemetryVal::TelemetryVal(telemetry::IntGaugeFamily) : OpaqueVal(int_gauge_metric_family_type) { }

TelemetryVal::TelemetryVal(telemetry::DblGauge) : OpaqueVal(dbl_gauge_metric_type) { }

TelemetryVal::TelemetryVal(telemetry::DblGaugeFamily) : OpaqueVal(dbl_gauge_metric_family_type) { }

TelemetryVal::TelemetryVal(telemetry::IntHistogram) : OpaqueVal(int_histogram_metric_type) { }

TelemetryVal::TelemetryVal(telemetry::IntHistogramFamily)
	: OpaqueVal(int_histogram_metric_family_type)
	{
	}

TelemetryVal::TelemetryVal(telemetry::DblHistogram) : OpaqueVal(dbl_histogram_metric_type) { }

TelemetryVal::TelemetryVal(telemetry::DblHistogramFamily)
	: OpaqueVal(dbl_histogram_metric_family_type)
	{
	}

	}
