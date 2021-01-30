// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/OpaqueVal.h"

#include <memory>

#include <broker/data.hh>
#include <broker/error.hh>

#include "zeek/CompHash.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Desc.h"
#include "zeek/Var.h"
#include "zeek/probabilistic/BloomFilter.h"
#include "zeek/probabilistic/CardinalityCounter.h"

namespace zeek {

// Helper to retrieve a broker value out of a broker::vector at a specified
// index, and casted to the expected destination type.
template<typename S, typename V, typename D>
inline bool get_vector_idx(const V& v, unsigned int i, D* dst)
	{
	if ( i >= v.size() )
		return false;

	auto x = caf::get_if<S>(&v[i]);
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

OpaqueVal::OpaqueVal(OpaqueTypePtr t) : Val(std::move(t))
	{}

OpaqueVal::~OpaqueVal()
	{
	}

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
	auto v = caf::get_if<broker::vector>(&data);

	if ( ! (v && v->size() == 2) )
		return nullptr;

	auto type = caf::get_if<std::string>(&(*v)[0]);
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
	auto v = caf::get_if<broker::vector>(&data);
	if ( ! (v && v->size() == 2) )
		return nullptr;

	auto by_name = caf::get_if<bool>(&(*v)[0]);
	if ( ! by_name )
		return nullptr;

	if ( *by_name )
		{
		auto name = caf::get_if<std::string>(&(*v)[1]);
		if ( ! name )
			return nullptr;

		const auto& id = detail::global_scope()->Find(*name);
		if ( ! id )
			return nullptr;

		if ( ! id->IsType() )
			return nullptr;

		return id->GetType();
		}

	auto tag = caf::get_if<uint64_t>(&(*v)[1]);
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
	}

MD5Val::~MD5Val()
	{
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
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
		detail::hash_update(h, (const u_char *) d.Bytes(), d.Len());
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

		EVP_MD_CTX_copy_ex(out->ctx, ctx);
		}

	return state->NewClone(this, std::move(out));
	}

bool MD5Val::DoInit()
	{
	assert(! IsValid());
	ctx = detail::hash_init(detail::Hash_MD5);
	return true;
	}

bool MD5Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	detail::hash_update(ctx, data, size);
	return true;
	}

StringValPtr MD5Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->EmptyString();

	u_char digest[MD5_DIGEST_LENGTH];
	detail::hash_final(ctx, digest);
	return make_intrusive<StringVal>(detail::md5_digest_print(digest));
	}

IMPLEMENT_OPAQUE_VALUE(MD5Val)

broker::expected<broker::data> MD5Val::DoSerialize() const
	{
	if ( ! IsValid() )
		return {broker::vector{false}};

	MD5_CTX* md = (MD5_CTX*) EVP_MD_CTX_md_data(ctx);

	broker::vector d = {
	    true,
	    static_cast<uint64_t>(md->A),
	    static_cast<uint64_t>(md->B),
	    static_cast<uint64_t>(md->C),
	    static_cast<uint64_t>(md->D),
	    static_cast<uint64_t>(md->Nl),
	    static_cast<uint64_t>(md->Nh),
	    static_cast<uint64_t>(md->num)
	};

	for ( int i = 0; i < MD5_LBLOCK; ++i )
		d.emplace_back(static_cast<uint64_t>(md->data[i]));

	return {std::move(d)};
	}

bool MD5Val::DoUnserialize(const broker::data& data)
	{
	auto d = caf::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	auto valid = caf::get_if<bool>(&(*d)[0]);
	if ( ! valid )
		return false;

	if ( ! *valid )
		{
		assert(! IsValid()); // default set by ctor
		return true;
		}

	Init();
	MD5_CTX* md = (MD5_CTX*) EVP_MD_CTX_md_data(ctx);

	if ( ! get_vector_idx<uint64_t>(*d, 1, &md->A) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 2, &md->B) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 3, &md->C) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 4, &md->D) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 5, &md->Nl) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 6, &md->Nh) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 7, &md->num) )
		return false;

	for ( int i = 0; i < MD5_LBLOCK; ++i )
		{
		if ( ! get_vector_idx<uint64_t>(*d, 8 + i, &md->data[i]) )
			return false;
		}

	return true;
	}

SHA1Val::SHA1Val() : HashVal(sha1_type)
	{
	}

SHA1Val::~SHA1Val()
	{
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
	}

ValPtr SHA1Val::DoClone(CloneState* state)
	{
	auto out = make_intrusive<SHA1Val>();

	if ( IsValid() )
		{
		if ( ! out->Init() )
			return nullptr;

		EVP_MD_CTX_copy_ex(out->ctx, ctx);
		}

	return state->NewClone(this, std::move(out));
	}

bool SHA1Val::DoInit()
	{
	assert(! IsValid());
	ctx = detail::hash_init(detail::Hash_SHA1);
	return true;
	}

bool SHA1Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	detail::hash_update(ctx, data, size);
	return true;
	}

StringValPtr SHA1Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->EmptyString();

	u_char digest[SHA_DIGEST_LENGTH];
	detail::hash_final(ctx, digest);
	return make_intrusive<StringVal>(detail::sha1_digest_print(digest));
	}

IMPLEMENT_OPAQUE_VALUE(SHA1Val)

broker::expected<broker::data> SHA1Val::DoSerialize() const
	{
	if ( ! IsValid() )
		return {broker::vector{false}};

	SHA_CTX* md = (SHA_CTX*) EVP_MD_CTX_md_data(ctx);

	broker::vector d = {
	    true,
	    static_cast<uint64_t>(md->h0),
	    static_cast<uint64_t>(md->h1),
	    static_cast<uint64_t>(md->h2),
	    static_cast<uint64_t>(md->h3),
	    static_cast<uint64_t>(md->h4),
	    static_cast<uint64_t>(md->Nl),
	    static_cast<uint64_t>(md->Nh),
	    static_cast<uint64_t>(md->num)
	};

	for ( int i = 0; i < SHA_LBLOCK; ++i )
		d.emplace_back(static_cast<uint64_t>(md->data[i]));

	return {std::move(d)};
	}

bool SHA1Val::DoUnserialize(const broker::data& data)
	{
	auto d = caf::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	auto valid = caf::get_if<bool>(&(*d)[0]);
	if ( ! valid )
		return false;

	if ( ! *valid )
		{
		assert(! IsValid()); // default set by ctor
		return true;
		}

	Init();
	SHA_CTX* md = (SHA_CTX*) EVP_MD_CTX_md_data(ctx);

	if ( ! get_vector_idx<uint64_t>(*d, 1, &md->h0) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 2, &md->h1) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 3, &md->h2) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 4, &md->h3) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 5, &md->h4) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 6, &md->Nl) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 7, &md->Nh) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 8, &md->num) )
		return false;

	for ( int i = 0; i < SHA_LBLOCK; ++i )
		{
		if ( ! get_vector_idx<uint64_t>(*d, 9 + i, &md->data[i]) )
			return false;
		}

	return true;
	}

SHA256Val::SHA256Val() : HashVal(sha256_type)
	{
	}

SHA256Val::~SHA256Val()
	{
	if ( IsValid() )
		EVP_MD_CTX_free(ctx);
	}

ValPtr SHA256Val::DoClone(CloneState* state)
	{
	auto out = make_intrusive<SHA256Val>();

	if ( IsValid() )
		{
		if ( ! out->Init() )
			return nullptr;

		EVP_MD_CTX_copy_ex(out->ctx, ctx);
		}

	return state->NewClone(this, std::move(out));
	}

bool SHA256Val::DoInit()
	{
	assert( ! IsValid() );
	ctx = detail::hash_init(detail::Hash_SHA256);
	return true;
	}

bool SHA256Val::DoFeed(const void* data, size_t size)
	{
	if ( ! IsValid() )
		return false;

	detail::hash_update(ctx, data, size);
	return true;
	}

StringValPtr SHA256Val::DoGet()
	{
	if ( ! IsValid() )
		return val_mgr->EmptyString();

	u_char digest[SHA256_DIGEST_LENGTH];
	detail::hash_final(ctx, digest);
	return make_intrusive<StringVal>(detail::sha256_digest_print(digest));
	}

IMPLEMENT_OPAQUE_VALUE(SHA256Val)

broker::expected<broker::data> SHA256Val::DoSerialize() const
	{
	if ( ! IsValid() )
		return {broker::vector{false}};

	SHA256_CTX* md = (SHA256_CTX*) EVP_MD_CTX_md_data(ctx);

	broker::vector d = {
	    true,
	    static_cast<uint64_t>(md->Nl),
	    static_cast<uint64_t>(md->Nh),
	    static_cast<uint64_t>(md->num),
	    static_cast<uint64_t>(md->md_len)
	};

	for ( int i = 0; i < 8; ++i )
		d.emplace_back(static_cast<uint64_t>(md->h[i]));

	for ( int i = 0; i < SHA_LBLOCK; ++i )
		d.emplace_back(static_cast<uint64_t>(md->data[i]));

	return {std::move(d)};
	}

bool SHA256Val::DoUnserialize(const broker::data& data)
	{
	auto d = caf::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	auto valid = caf::get_if<bool>(&(*d)[0]);
	if ( ! valid )
		return false;

	if ( ! *valid )
		{
		assert(! IsValid()); // default set by ctor
		return true;
		}

	Init();
	SHA256_CTX* md = (SHA256_CTX*) EVP_MD_CTX_md_data(ctx);

	if ( ! get_vector_idx<uint64_t>(*d, 1, &md->Nl) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 2, &md->Nh) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 3, &md->num) )
		return false;
	if ( ! get_vector_idx<uint64_t>(*d, 4, &md->md_len) )
		return false;

	for ( int i = 0; i < 8; ++i )
		{
		if ( ! get_vector_idx<uint64_t>(*d, 5 + i, &md->h[i]) )
			return false;
		}

	for ( int i = 0; i < SHA_LBLOCK; ++i )
		{
		if ( ! get_vector_idx<uint64_t>(*d, 13 + i, &md->data[i]) )
			return false;
		}

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

IMPLEMENT_OPAQUE_VALUE(EntropyVal)

broker::expected<broker::data> EntropyVal::DoSerialize() const
	{
	broker::vector d =
		{
		static_cast<uint64_t>(state.totalc),
		static_cast<uint64_t>(state.mp),
		static_cast<uint64_t>(state.sccfirst),
		static_cast<uint64_t>(state.inmont),
		static_cast<uint64_t>(state.mcount),
		static_cast<uint64_t>(state.cexp),
		static_cast<uint64_t>(state.montex),
		static_cast<uint64_t>(state.montey),
		static_cast<uint64_t>(state.montepi),
		static_cast<uint64_t>(state.sccu0),
		static_cast<uint64_t>(state.scclast),
		static_cast<uint64_t>(state.scct1),
		static_cast<uint64_t>(state.scct2),
		static_cast<uint64_t>(state.scct3),
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
	auto d = caf::get_if<broker::vector>(&data);
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

BloomFilterVal::BloomFilterVal()
	: OpaqueVal(bloomfilter_type)
	{
	hash = nullptr;
	bloom_filter = nullptr;
	}

BloomFilterVal::BloomFilterVal(probabilistic::BloomFilter* bf)
	: OpaqueVal(bloomfilter_type)
	{
	hash = nullptr;
	bloom_filter = bf;
	}

ValPtr BloomFilterVal::DoClone(CloneState* state)
	{
	if ( bloom_filter )
		{
		auto bf = make_intrusive<BloomFilterVal>(bloom_filter->Clone());
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

BloomFilterValPtr BloomFilterVal::Merge(const BloomFilterVal* x,
                                        const BloomFilterVal* y)
	{
	if ( x->Type() && // any one 0 is ok here
	     y->Type() &&
	     ! same_type(x->Type(), y->Type()) )
		{
		reporter->Error("cannot merge Bloom filters with different types");
		return nullptr;
		}

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

	if ( x->Type() && ! merged->Typify(x->Type()) )
		{
		reporter->Error("failed to set type on merged Bloom filter");
		return nullptr;
		}

	return merged;
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
	auto v = caf::get_if<broker::vector>(&data);

	if ( ! (v && v->size() == 2) )
		return false;

	auto no_type = caf::get_if<broker::none>(&(*v)[0]);
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
	return state->NewClone(this,
			       make_intrusive<CardinalityVal>(new probabilistic::detail::CardinalityCounter(*c)));
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
	auto v = caf::get_if<broker::vector>(&data);

	if ( ! (v && v->size() == 2) )
		return false;

	auto no_type = caf::get_if<broker::none>(&(*v)[0]);
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

ParaglobVal::ParaglobVal(std::unique_ptr<paraglob::Paraglob> p)
: OpaqueVal(paraglob_type)
	{
	this->internal_paraglob = std::move(p);
	}

VectorValPtr ParaglobVal::Get(StringVal* &pattern)
	{
	auto rval = make_intrusive<VectorVal>(id::string_vec);
	std::string string_pattern (reinterpret_cast<const char*>(pattern->Bytes()), pattern->Len());

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
	for (uint8_t a : *(iv.get()))
		d.emplace_back(static_cast<uint64_t>(a));
	return {std::move(d)};
	}

bool ParaglobVal::DoUnserialize(const broker::data& data)
	{
	auto d = caf::get_if<broker::vector>(&data);
	if ( ! d )
		return false;

	std::unique_ptr<std::vector<uint8_t>> iv (new std::vector<uint8_t>);
	iv->resize(d->size());

	for (std::vector<broker::data>::size_type i = 0; i < d->size(); ++i)
		{
		if ( ! get_vector_idx<uint64_t>(*d, i, iv.get()->data() + i) )
			return false;
		}

	try
		{
		this->internal_paraglob = std::make_unique<paraglob::Paraglob>(std::move(iv));
		}
	catch (const paraglob::underflow_error& e)
		{
		reporter->Error("Paraglob underflow error -> %s", e.what());
		return false;
		}
	catch (const paraglob::overflow_error& e)
		{
		reporter->Error("Paraglob overflow error -> %s", e.what());
		return false;
		}

	return true;
	}

ValPtr ParaglobVal::DoClone(CloneState* state)
	{
	try {
		return make_intrusive<ParaglobVal>
			(std::make_unique<paraglob::Paraglob>(this->internal_paraglob->serialize()));
		}
	catch (const paraglob::underflow_error& e)
		{
		reporter->Error("Paraglob underflow error while cloning -> %s", e.what());
		return nullptr;
		}
	catch (const paraglob::overflow_error& e)
		{
		reporter->Error("Paraglob overflow error while cloning -> %s", e.what());
		return nullptr;
		}
	}

}
