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
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <memory>

#include "zeek/CompHash.h"
#include "zeek/Desc.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Var.h"
#include "zeek/broker/Data.h"
#include "zeek/digest.h"
#include "zeek/probabilistic/BloomFilter.h"
#include "zeek/probabilistic/CardinalityCounter.h"

#if ( OPENSSL_VERSION_NUMBER < 0x10100000L ) || defined(LIBRESSL_VERSION_NUMBER)
inline void* EVP_MD_CTX_md_data(const EVP_MD_CTX* ctx) { return ctx->md_data; }
#endif

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/md5.h>
#endif

namespace zeek {

// Helper to retrieve a broker count out of a list at a specified index, and
// casted to the expected destination type.
template<typename V, typename D>
bool get_vector_idx_if_count(V& v, size_t i, D* dst) {
    if ( i >= v.Size() || ! v[i].IsCount() )
        return false;

    *dst = static_cast<D>(v[i].ToCount());
    return true;
}

OpaqueMgr* OpaqueMgr::mgr() {
    static OpaqueMgr mgr;
    return &mgr;
}

OpaqueVal::OpaqueVal(OpaqueTypePtr t) : Val(std::move(t)) {}

const std::string& OpaqueMgr::TypeID(const OpaqueVal* v) const {
    auto x = _types.find(v->OpaqueName());

    if ( x == _types.end() )
        reporter->InternalError("OpaqueMgr::TypeID: opaque type %s not registered", v->OpaqueName());

    return x->first;
}

OpaqueValPtr OpaqueMgr::Instantiate(const std::string& id) const {
    auto x = _types.find(id);
    return x != _types.end() ? (*x->second)() : nullptr;
}

broker::expected<broker::data> OpaqueVal::Serialize() const {
    if ( auto res = SerializeData() )
        return zeek::detail::BrokerDataAccess::Unbox(*res);
    return {broker::make_error(broker::ec::serialization_failed)};
}

std::optional<BrokerData> OpaqueVal::SerializeData() const {
    auto type = OpaqueMgr::mgr()->TypeID(this);

    auto d = DoSerializeData();
    if ( ! d )
        return std::nullopt;

    BrokerListBuilder builder;
    builder.Add(std::move(type));
    builder.Add(std::move(*d));
    return std::move(builder).Build();
}

OpaqueValPtr OpaqueVal::Unserialize(const broker::data& data) { return UnserializeData(BrokerDataView(&data)); }

OpaqueValPtr OpaqueVal::UnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return nullptr;

    return UnserializeData(data.ToList());
}

OpaqueValPtr OpaqueVal::UnserializeData(BrokerListView v) {
    if ( v.Size() != 2 || ! v[0].IsString() )
        return nullptr;

    auto type = v[0].ToString();

    auto val = OpaqueMgr::mgr()->Instantiate(std::string{type});
    if ( ! val )
        return nullptr;

    if ( ! val->DoUnserializeData(v[1]) )
        return nullptr;

    return val;
}

broker::expected<broker::data> OpaqueVal::DoSerialize() const {
    return {broker::make_error(broker::ec::serialization_failed)};
}

std::optional<BrokerData> OpaqueVal::DoSerializeData() const {
    if ( auto res = DoSerialize() ) {
        return BrokerData{std::move(*res)};
    }
    return std::nullopt;
}

bool OpaqueVal::DoUnserialize(const broker::data&) { return false; }

bool OpaqueVal::DoUnserializeData(BrokerDataView data) {
    return DoUnserialize(zeek::detail::BrokerDataAccess::Unbox(data));
}

std::optional<BrokerData> OpaqueVal::SerializeType(const TypePtr& t) {
    if ( t->InternalType() == TYPE_INTERNAL_ERROR )
        return std::nullopt;

    BrokerListBuilder builder;

    if ( t->InternalType() == TYPE_INTERNAL_OTHER ) {
        // Serialize by name.
        assert(! t->GetName().empty());
        builder.Add(true);
        builder.Add(t->GetName());
    }
    else {
        // A base type.
        builder.Add(false);
        builder.Add(static_cast<uint64_t>(t->Tag()));
    }

    return {std::move(builder).Build()};
}

TypePtr OpaqueVal::UnserializeType(BrokerDataView data) {
    if ( ! data.IsList() )
        return nullptr;

    auto v = data.ToList();

    if ( v.Size() != 2 || ! v[0].IsBool() )
        return nullptr;

    if ( v[0].ToBool() ) // Get by name?
    {
        if ( ! v[1].IsString() )
            return nullptr;

        const auto& id = detail::global_scope()->Find(v[1].ToString());
        if ( ! id )
            return nullptr;

        if ( ! id->IsType() )
            return nullptr;

        return id->GetType();
    }

    if ( ! v[1].IsCount() )
        return nullptr;

    return base_type(static_cast<TypeTag>(v[1].ToCount()));
}

ValPtr OpaqueVal::DoClone(CloneState* state) {
    auto d = OpaqueVal::SerializeData();
    if ( ! d )
        return nullptr;

    auto rval = OpaqueVal::UnserializeData(d->AsView());
    return state->NewClone(this, std::move(rval));
}

void OpaqueVal::ValDescribe(ODesc* d) const { d->Add(util::fmt("<opaque of %s>", OpaqueName())); }

void OpaqueVal::ValDescribeReST(ODesc* d) const { d->Add(util::fmt("<opaque of %s>", OpaqueName())); }

bool HashVal::IsValid() const { return valid; }

bool HashVal::Init() {
    if ( valid )
        return false;

    valid = DoInit();
    return valid;
}

StringValPtr HashVal::Get() {
    if ( ! valid )
        return val_mgr->EmptyString();

    auto result = DoGet();
    valid = false;
    return result;
}

bool HashVal::Feed(const void* data, size_t size) {
    if ( valid )
        return DoFeed(data, size);

    Error("attempt to update an invalid opaque hash value");
    return false;
}

bool HashVal::DoInit() {
    assert(! "missing implementation of DoInit()");
    return false;
}

bool HashVal::DoFeed(const void*, size_t) {
    assert(! "missing implementation of DoFeed()");
    return false;
}

StringValPtr HashVal::DoGet() {
    assert(! "missing implementation of DoGet()");
    return val_mgr->EmptyString();
}

HashVal::HashVal(OpaqueTypePtr t) : OpaqueVal(std::move(t)) { valid = false; }

namespace {

constexpr size_t MD5VAL_STATE_SIZE = sizeof(MD5_CTX);

constexpr size_t SHA1VAL_STATE_SIZE = sizeof(SHA_CTX);

constexpr size_t SHA256VAL_STATE_SIZE = sizeof(SHA256_CTX);

#if ( OPENSSL_VERSION_NUMBER < 0x30000000L ) || defined(LIBRESSL_VERSION_NUMBER)

// -- MD5

auto* to_native_ptr(MD5Val::StatePtr ptr) { return reinterpret_cast<EVP_MD_CTX*>(ptr); }

auto* to_digest_ptr(MD5Val::StatePtr ptr) { return reinterpret_cast<detail::HashDigestState*>(ptr); }

void do_init(MD5Val::StatePtr& ptr) { ptr = reinterpret_cast<MD5Val::StatePtr>(detail::hash_init(detail::Hash_MD5)); }

void do_clone(MD5Val::StatePtr out, MD5Val::StatePtr in) { hash_copy(to_digest_ptr(out), to_digest_ptr(in)); }

void do_feed(MD5Val::StatePtr ptr, const void* data, size_t size) {
    detail::hash_update(to_digest_ptr(ptr), data, size);
}

void do_get(MD5Val::StatePtr ptr, u_char* digest) { detail::hash_final_no_free(to_digest_ptr(ptr), digest); }

std::string do_serialize(MD5Val::StatePtr ptr) {
    auto* md = reinterpret_cast<MD5_CTX*>(EVP_MD_CTX_md_data(to_native_ptr(ptr)));
    return {reinterpret_cast<const char*>(md), sizeof(MD5_CTX)};
}

void do_unserialize(MD5Val::StatePtr ptr, const char* bytes, size_t len) {
    auto* md = reinterpret_cast<MD5_CTX*>(EVP_MD_CTX_md_data(to_native_ptr(ptr)));
    memcpy(md, bytes, len);
}

void do_destroy(MD5Val::StatePtr ptr) { hash_state_free(to_digest_ptr(ptr)); }

// -- SHA1

auto* to_native_ptr(SHA1Val::StatePtr ptr) { return reinterpret_cast<EVP_MD_CTX*>(ptr); }

auto* to_digest_ptr(SHA1Val::StatePtr ptr) { return reinterpret_cast<detail::HashDigestState*>(ptr); }

void do_init(SHA1Val::StatePtr& ptr) {
    ptr = reinterpret_cast<SHA1Val::StatePtr>(detail::hash_init(detail::Hash_SHA1));
}

void do_clone(SHA1Val::StatePtr out, SHA1Val::StatePtr in) { detail::hash_copy(to_digest_ptr(out), to_digest_ptr(in)); }

void do_feed(SHA1Val::StatePtr ptr, const void* data, size_t size) {
    detail::hash_update(to_digest_ptr(ptr), data, size);
}

void do_get(SHA1Val::StatePtr ptr, u_char* digest) { detail::hash_final_no_free(to_digest_ptr(ptr), digest); }

std::string do_serialize(SHA1Val::StatePtr ptr) {
    auto* md = reinterpret_cast<SHA_CTX*>(EVP_MD_CTX_md_data(to_native_ptr(ptr)));
    return {reinterpret_cast<const char*>(md), sizeof(SHA_CTX)};
}

void do_unserialize(SHA1Val::StatePtr ptr, const char* bytes, size_t len) {
    auto* md = reinterpret_cast<SHA_CTX*>(EVP_MD_CTX_md_data(to_native_ptr(ptr)));
    memcpy(md, bytes, len);
}

void do_destroy(SHA1Val::StatePtr ptr) { hash_state_free(to_digest_ptr(ptr)); }

// -- SHA256

auto* to_native_ptr(SHA256Val::StatePtr ptr) { return reinterpret_cast<EVP_MD_CTX*>(ptr); }

auto* to_digest_ptr(SHA256Val::StatePtr ptr) { return reinterpret_cast<detail::HashDigestState*>(ptr); }

void do_init(SHA256Val::StatePtr& ptr) {
    ptr = reinterpret_cast<SHA256Val::StatePtr>(detail::hash_init(detail::Hash_SHA256));
}

void do_clone(SHA256Val::StatePtr out, SHA256Val::StatePtr in) {
    detail::hash_copy(to_digest_ptr(out), to_digest_ptr(in));
}

void do_feed(SHA256Val::StatePtr ptr, const void* data, size_t size) {
    detail::hash_update(to_digest_ptr(ptr), data, size);
}

void do_get(SHA256Val::StatePtr ptr, u_char* digest) { detail::hash_final_no_free(to_digest_ptr(ptr), digest); }

std::string do_serialize(SHA256Val::StatePtr ptr) {
    auto* md = reinterpret_cast<SHA256_CTX*>(EVP_MD_CTX_md_data(to_native_ptr(ptr)));
    return {reinterpret_cast<const char*>(md), sizeof(SHA256_CTX)};
}

void do_unserialize(SHA256Val::StatePtr ptr, const char* bytes, size_t len) {
    auto* md = reinterpret_cast<SHA256_CTX*>(EVP_MD_CTX_md_data(to_native_ptr(ptr)));
    memcpy(md, bytes, len);
}

void do_destroy(SHA256Val::StatePtr ptr) { hash_state_free(to_digest_ptr(ptr)); }

#else

// -- MD5

auto* to_native_ptr(MD5Val::StatePtr ptr) { return reinterpret_cast<MD5_CTX*>(ptr); }

void do_init(MD5Val::StatePtr& ptr) {
    auto ctx = new MD5_CTX;
    MD5_Init(ctx);
    ptr = reinterpret_cast<MD5Val::StatePtr>(ctx);
}

void do_clone(MD5Val::StatePtr out, MD5Val::StatePtr in) { *to_native_ptr(out) = *to_native_ptr(in); }

void do_feed(MD5Val::StatePtr ptr, const void* data, size_t size) { MD5_Update(to_native_ptr(ptr), data, size); }

void do_get(MD5Val::StatePtr ptr, u_char* digest) { MD5_Final(digest, to_native_ptr(ptr)); }

std::string do_serialize(MD5Val::StatePtr ptr) { return {reinterpret_cast<const char*>(ptr), sizeof(MD5_CTX)}; }

void do_unserialize(MD5Val::StatePtr ptr, const char* bytes, size_t len) { memcpy(ptr, bytes, len); }

void do_destroy(MD5Val::StatePtr ptr) { delete to_native_ptr(ptr); }

// -- SHA1

auto* to_native_ptr(SHA1Val::StatePtr ptr) { return reinterpret_cast<SHA_CTX*>(ptr); }

void do_init(SHA1Val::StatePtr& ptr) {
    auto ctx = new SHA_CTX;
    SHA1_Init(ctx);
    ptr = reinterpret_cast<SHA1Val::StatePtr>(ctx);
}

void do_clone(SHA1Val::StatePtr out, SHA1Val::StatePtr in) { *to_native_ptr(out) = *to_native_ptr(in); }

void do_feed(SHA1Val::StatePtr ptr, const void* data, size_t size) { SHA1_Update(to_native_ptr(ptr), data, size); }

void do_get(SHA1Val::StatePtr ptr, u_char* digest) { SHA1_Final(digest, to_native_ptr(ptr)); }

std::string do_serialize(SHA1Val::StatePtr ptr) { return {reinterpret_cast<const char*>(ptr), sizeof(SHA_CTX)}; }

void do_unserialize(SHA1Val::StatePtr ptr, const char* bytes, size_t len) { memcpy(ptr, bytes, len); }

void do_destroy(SHA1Val::StatePtr ptr) { delete to_native_ptr(ptr); }

// -- SHA256

auto* to_native_ptr(SHA256Val::StatePtr ptr) { return reinterpret_cast<SHA256_CTX*>(ptr); }

void do_init(SHA256Val::StatePtr& ptr) {
    auto ctx = new SHA256_CTX;
    SHA256_Init(ctx);
    ptr = reinterpret_cast<SHA256Val::StatePtr>(ctx);
}

void do_clone(SHA256Val::StatePtr out, SHA256Val::StatePtr in) { *to_native_ptr(out) = *to_native_ptr(in); }

void do_feed(SHA256Val::StatePtr ptr, const void* data, size_t size) { SHA256_Update(to_native_ptr(ptr), data, size); }

void do_get(SHA256Val::StatePtr ptr, u_char* digest) { SHA256_Final(digest, to_native_ptr(ptr)); }

std::string do_serialize(SHA256Val::StatePtr ptr) { return {reinterpret_cast<const char*>(ptr), sizeof(SHA256_CTX)}; }

void do_unserialize(SHA256Val::StatePtr ptr, const char* bytes, size_t len) { memcpy(ptr, bytes, len); }

void do_destroy(SHA256Val::StatePtr ptr) { delete to_native_ptr(ptr); }

#endif

} // namespace

MD5Val::MD5Val() : HashVal(md5_type) {}

MD5Val::~MD5Val() { do_destroy(ctx); }

void HashVal::digest_one(detail::HashDigestState* h, const Val* v) {
    if ( v->GetType()->Tag() == TYPE_STRING ) {
        const String* str = v->AsString();
        detail::hash_update(h, str->Bytes(), str->Len());
    }
    else {
        ODesc d(DESC_BINARY);
        v->Describe(&d);
        detail::hash_update(h, (const u_char*)d.Bytes(), d.Len());
    }
}

void HashVal::digest_one(detail::HashDigestState* h, const ValPtr& v) { digest_one(h, v.get()); }

ValPtr MD5Val::DoClone(CloneState* state) {
    auto out = make_intrusive<MD5Val>();

    if ( IsValid() ) {
        if ( ! out->Init() )
            return nullptr;
        do_clone(out->ctx, ctx);
    }

    return state->NewClone(this, std::move(out));
}

bool MD5Val::DoInit() {
    assert(! IsValid());
    do_init(ctx);
    return true;
}

bool MD5Val::DoFeed(const void* data, size_t size) {
    if ( ! IsValid() )
        return false;
    do_feed(ctx, data, size);
    return true;
}

StringValPtr MD5Val::DoGet() {
    if ( ! IsValid() )
        return val_mgr->EmptyString();

    u_char digest[ZEEK_MD5_DIGEST_LENGTH];
    do_get(ctx, digest);
    return make_intrusive<StringVal>(detail::md5_digest_print(digest));
}

IMPLEMENT_OPAQUE_VALUE(MD5Val)

std::optional<BrokerData> MD5Val::DoSerializeData() const {
    BrokerListBuilder builder;

    if ( ! IsValid() ) {
        builder.Add(false);
        return std::move(builder).Build();
    }

    builder.Reserve(2);
    builder.Add(true);
    builder.Add(do_serialize(ctx));
    return std::move(builder).Build();
}

bool MD5Val::DoUnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return false;
    auto d = data.ToList();

    if ( d.IsEmpty() || ! d[0].IsBool() )
        return false;

    if ( ! d[0].ToBool() ) {
        assert(! IsValid()); // default set by ctor
        return true;
    }

    if ( d.Size() != 2 || ! d[1].IsString() )
        return false;

    auto s = d[1].ToString();

    if ( s.size() != MD5VAL_STATE_SIZE )
        return false;

    Init();
    do_unserialize(ctx, s.data(), s.size());
    return true;
}

SHA1Val::SHA1Val() : HashVal(sha1_type) {}

SHA1Val::~SHA1Val() { do_destroy(ctx); }

ValPtr SHA1Val::DoClone(CloneState* state) {
    auto out = make_intrusive<SHA1Val>();

    if ( IsValid() ) {
        if ( ! out->Init() )
            return nullptr;

        do_clone(out->ctx, ctx);
    }

    return state->NewClone(this, std::move(out));
}

bool SHA1Val::DoInit() {
    assert(! IsValid());
    do_init(ctx);
    return true;
}

bool SHA1Val::DoFeed(const void* data, size_t size) {
    if ( ! IsValid() )
        return false;

    do_feed(ctx, data, size);
    return true;
}

StringValPtr SHA1Val::DoGet() {
    if ( ! IsValid() )
        return val_mgr->EmptyString();

    u_char digest[SHA_DIGEST_LENGTH];
    do_get(ctx, digest);
    return make_intrusive<StringVal>(detail::sha1_digest_print(digest));
}

IMPLEMENT_OPAQUE_VALUE(SHA1Val)

std::optional<BrokerData> SHA1Val::DoSerializeData() const {
    BrokerListBuilder builder;

    if ( ! IsValid() ) {
        builder.Add(false);
        return std::move(builder).Build();
    }

    builder.Reserve(2);
    builder.Add(true);
    builder.Add(do_serialize(ctx));
    return std::move(builder).Build();
}

bool SHA1Val::DoUnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return false;

    auto d = data.ToList();

    if ( d.IsEmpty() || ! d[0].IsBool() )
        return false;

    if ( ! d[0].ToBool() ) {
        assert(! IsValid()); // default set by ctor
        return true;
    }

    if ( d.Size() != 2 || ! d[1].IsString() )
        return false;

    auto s = d[1].ToString();

    if ( s.size() != SHA1VAL_STATE_SIZE )
        return false;

    Init();
    do_unserialize(ctx, s.data(), s.size());
    return true;
}

SHA256Val::SHA256Val() : HashVal(sha256_type) {}

SHA256Val::~SHA256Val() {
    if ( ctx != nullptr )
        do_destroy(ctx);
}

ValPtr SHA256Val::DoClone(CloneState* state) {
    auto out = make_intrusive<SHA256Val>();

    if ( IsValid() ) {
        if ( ! out->Init() )
            return nullptr;

        do_clone(out->ctx, ctx);
    }

    return state->NewClone(this, std::move(out));
}

bool SHA256Val::DoInit() {
    assert(! IsValid());
    do_init(ctx);
    return true;
}

bool SHA256Val::DoFeed(const void* data, size_t size) {
    if ( ! IsValid() )
        return false;

    do_feed(ctx, data, size);
    return true;
}

StringValPtr SHA256Val::DoGet() {
    if ( ! IsValid() )
        return val_mgr->EmptyString();

    u_char digest[SHA256_DIGEST_LENGTH];
    do_get(ctx, digest);
    return make_intrusive<StringVal>(detail::sha256_digest_print(digest));
}

IMPLEMENT_OPAQUE_VALUE(SHA256Val)

std::optional<BrokerData> SHA256Val::DoSerializeData() const {
    BrokerListBuilder builder;

    if ( ! IsValid() ) {
        builder.Add(false);
        return std::move(builder).Build();
    }

    builder.Add(true);
    builder.Add(do_serialize(ctx));
    return std::move(builder).Build();
}

bool SHA256Val::DoUnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return false;

    auto d = data.ToList();

    if ( d.IsEmpty() || ! d[0].IsBool() )
        return false;

    if ( ! d[0].ToBool() ) {
        assert(! IsValid()); // default set by ctor
        return true;
    }

    if ( d.Size() != 2 || ! d[1].IsString() )
        return false;

    auto s = d[1].ToString();

    if ( s.size() != SHA256VAL_STATE_SIZE )
        return false;

    Init();
    do_unserialize(ctx, s.data(), s.size());
    return true;
}

EntropyVal::EntropyVal() : OpaqueVal(entropy_type) {}

bool EntropyVal::Feed(const void* data, size_t size) {
    state.add(data, size);
    return true;
}

bool EntropyVal::Get(double* r_ent, double* r_chisq, double* r_mean, double* r_montepicalc, double* r_scc) {
    state.end(r_ent, r_chisq, r_mean, r_montepicalc, r_scc);
    return true;
}

IMPLEMENT_OPAQUE_VALUE(EntropyVal)

std::optional<BrokerData> EntropyVal::DoSerializeData() const {
    constexpr size_t numMembers = 14; // RandTest has 14 non-array members.

    BrokerListBuilder builder;
    builder.Reserve(numMembers + std::size(state.ccount) + std::size(state.monte));

    builder.Add(static_cast<uint64_t>(state.totalc));
    builder.Add(static_cast<uint64_t>(state.mp));
    builder.Add(static_cast<uint64_t>(state.sccfirst));
    builder.Add(static_cast<uint64_t>(state.inmont));
    builder.Add(static_cast<uint64_t>(state.mcount));
    builder.Add(static_cast<uint64_t>(state.cexp));
    builder.Add(static_cast<uint64_t>(state.montex));
    builder.Add(static_cast<uint64_t>(state.montey));
    builder.Add(static_cast<uint64_t>(state.montepi));
    builder.Add(static_cast<uint64_t>(state.sccu0));
    builder.Add(static_cast<uint64_t>(state.scclast));
    builder.Add(static_cast<uint64_t>(state.scct1));
    builder.Add(static_cast<uint64_t>(state.scct2));
    builder.Add(static_cast<uint64_t>(state.scct3));

    for ( auto bin : state.ccount )
        builder.Add(static_cast<uint64_t>(bin));

    for ( auto val : state.monte )
        builder.Add(static_cast<uint64_t>(val));

    return std::move(builder).Build();
}

bool EntropyVal::DoUnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return false;

    auto index = size_t{0};

    auto d = data.ToList();

    if ( ! get_vector_idx_if_count(d, index++, &state.totalc) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.mp) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.sccfirst) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.inmont) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.mcount) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.cexp) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.montex) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.montey) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.montepi) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.sccu0) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.scclast) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.scct1) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.scct2) )
        return false;
    if ( ! get_vector_idx_if_count(d, index++, &state.scct3) )
        return false;

    for ( auto& bin : state.ccount ) {
        if ( ! get_vector_idx_if_count(d, index++, &bin) )
            return false;
    }

    for ( auto& val : state.monte ) {
        if ( ! get_vector_idx_if_count(d, index++, &val) )
            return false;
    }

    return true;
}

BloomFilterVal::BloomFilterVal() : OpaqueVal(bloomfilter_type) {
    hash = nullptr;
    bloom_filter = nullptr;
}

BloomFilterVal::BloomFilterVal(probabilistic::BloomFilter* bf) : OpaqueVal(bloomfilter_type) {
    hash = nullptr;
    bloom_filter = bf;
}

ValPtr BloomFilterVal::DoClone(CloneState* state) {
    if ( bloom_filter ) {
        auto bf = make_intrusive<BloomFilterVal>(bloom_filter->Clone());
        assert(type);
        bf->Typify(type);
        return state->NewClone(this, std::move(bf));
    }

    return state->NewClone(this, make_intrusive<BloomFilterVal>());
}

bool BloomFilterVal::Typify(TypePtr arg_type) {
    if ( type )
        return false;

    type = std::move(arg_type);

    auto tl = make_intrusive<TypeList>(type);
    tl->Append(type);
    hash = new detail::CompositeHash(std::move(tl));

    return true;
}

void BloomFilterVal::Add(const Val* val) {
    auto key = hash->MakeHashKey(*val, true);
    bloom_filter->Add(key.get());
}

bool BloomFilterVal::Decrement(const Val* val) {
    auto key = hash->MakeHashKey(*val, true);
    return bloom_filter->Decrement(key.get());
}

size_t BloomFilterVal::Count(const Val* val) const {
    auto key = hash->MakeHashKey(*val, true);
    size_t cnt = bloom_filter->Count(key.get());
    return cnt;
}

void BloomFilterVal::Clear() { bloom_filter->Clear(); }

bool BloomFilterVal::Empty() const { return bloom_filter->Empty(); }

std::string BloomFilterVal::InternalState() const { return bloom_filter->InternalState(); }

BloomFilterValPtr BloomFilterVal::Merge(const BloomFilterVal* x, const BloomFilterVal* y) {
    if ( x->Type() && // any one 0 is ok here
         y->Type() && ! same_type(x->Type(), y->Type()) ) {
        reporter->Error("cannot merge Bloom filters with different types");
        return nullptr;
    }

    auto final_type = x->Type() ? x->Type() : y->Type();

    if ( typeid(*x->bloom_filter) != typeid(*y->bloom_filter) ) {
        reporter->Error("cannot merge different Bloom filter types");
        return nullptr;
    }

    probabilistic::BloomFilter* copy = x->bloom_filter->Clone();

    if ( ! copy->Merge(y->bloom_filter) ) {
        delete copy;
        reporter->Error("failed to merge Bloom filter");
        return nullptr;
    }

    auto merged = make_intrusive<BloomFilterVal>(copy);

    if ( final_type && ! merged->Typify(final_type) ) {
        reporter->Error("failed to set type on merged Bloom filter");
        return nullptr;
    }

    return merged;
}

BloomFilterValPtr BloomFilterVal::Intersect(const BloomFilterVal* x, const BloomFilterVal* y) {
    if ( x->Type() && // any one 0 is ok here
         y->Type() && ! same_type(x->Type(), y->Type()) ) {
        reporter->Error("cannot merge Bloom filters with different types");
        return nullptr;
    }

    if ( typeid(*x->bloom_filter) != typeid(*y->bloom_filter) ) {
        reporter->Error("cannot intersect different Bloom filter types");
        return nullptr;
    }

    auto intersected_bf = x->bloom_filter->Intersect(y->bloom_filter);

    if ( ! intersected_bf ) {
        reporter->Error("failed to intersect Bloom filter");
        return nullptr;
    }

    auto final_type = x->Type() ? x->Type() : y->Type();

    auto intersected = make_intrusive<BloomFilterVal>(intersected_bf);

    if ( final_type && ! intersected->Typify(final_type) ) {
        reporter->Error("Failed to set type on intersected bloom filter");
        return nullptr;
    }

    return intersected;
}

BloomFilterVal::~BloomFilterVal() {
    delete hash;
    delete bloom_filter;
}

IMPLEMENT_OPAQUE_VALUE(BloomFilterVal)

std::optional<BrokerData> BloomFilterVal::DoSerializeData() const {
    BrokerListBuilder builder;

    if ( type ) {
        auto t = SerializeType(type);
        if ( ! t )
            return std::nullopt;

        builder.Add(std::move(*t));
    }
    else
        builder.AddNil();

    auto bf = bloom_filter->SerializeData();
    if ( ! bf )
        return std::nullopt;

    builder.Add(std::move(*bf));
    return std::move(builder).Build();
}

bool BloomFilterVal::DoUnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return false;

    auto v = data.ToList();

    if ( v.Size() != 2 )
        return false;

    if ( ! v[0].IsNil() ) {
        auto t = UnserializeType(v[0]);

        if ( ! (t && Typify(std::move(t))) )
            return false;
    }

    auto bf = probabilistic::BloomFilter::UnserializeData(v[1]);
    if ( ! bf )
        return false;

    bloom_filter = bf.release();
    return true;
}

CardinalityVal::CardinalityVal() : OpaqueVal(cardinality_type) {
    c = nullptr;
    hash = nullptr;
}

CardinalityVal::CardinalityVal(probabilistic::detail::CardinalityCounter* arg_c) : OpaqueVal(cardinality_type) {
    c = arg_c;
    hash = nullptr;
}

CardinalityVal::~CardinalityVal() {
    delete c;
    delete hash;
}

ValPtr CardinalityVal::DoClone(CloneState* state) {
    return state->NewClone(this, make_intrusive<CardinalityVal>(new probabilistic::detail::CardinalityCounter(*c)));
}

bool CardinalityVal::Typify(TypePtr arg_type) {
    if ( type )
        return false;

    type = std::move(arg_type);

    auto tl = make_intrusive<TypeList>(type);
    tl->Append(type);
    hash = new detail::CompositeHash(std::move(tl));

    return true;
}

void CardinalityVal::Add(const Val* val) {
    auto key = hash->MakeHashKey(*val, true);
    c->AddElement(key->Hash());
}

IMPLEMENT_OPAQUE_VALUE(CardinalityVal)

std::optional<BrokerData> CardinalityVal::DoSerializeData() const {
    BrokerListBuilder builder;
    builder.Reserve(2);

    if ( type ) {
        auto t = SerializeType(type);
        if ( ! t )
            return std::nullopt;

        builder.Add(std::move(*t));
    }
    else
        builder.AddNil();

    auto cs = c->Serialize();
    if ( ! cs )
        return std::nullopt;

    builder.Add(std::move(*cs));
    return std::move(builder).Build();
}

bool CardinalityVal::DoUnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return false;

    auto v = data.ToList();

    if ( v.Size() != 2 )
        return false;

    if ( ! v[0].IsNil() ) {
        auto t = UnserializeType(v[0]);

        if ( ! (t && Typify(std::move(t))) )
            return false;
    }

    auto cu = probabilistic::detail::CardinalityCounter::Unserialize(v[1]);
    if ( ! cu )
        return false;

    c = cu.release();
    return true;
}

ParaglobVal::ParaglobVal(std::unique_ptr<paraglob::Paraglob> p) : OpaqueVal(paraglob_type) {
    this->internal_paraglob = std::move(p);
}

VectorValPtr ParaglobVal::Get(StringVal*& pattern) {
    auto rval = make_intrusive<VectorVal>(id::string_vec);
    std::string string_pattern(reinterpret_cast<const char*>(pattern->Bytes()), pattern->Len());

    std::vector<std::string> matches = this->internal_paraglob->get(string_pattern);
    for ( size_t i = 0; i < matches.size(); i++ )
        rval->Assign(i, make_intrusive<StringVal>(matches.at(i)));

    return rval;
}

bool ParaglobVal::operator==(const ParaglobVal& other) const {
    return *(this->internal_paraglob) == *(other.internal_paraglob);
}

IMPLEMENT_OPAQUE_VALUE(ParaglobVal)

std::optional<BrokerData> ParaglobVal::DoSerializeData() const {
    std::unique_ptr<std::vector<uint8_t>> iv = this->internal_paraglob->serialize();
    BrokerListBuilder builder;
    builder.Reserve(iv->size());
    for ( uint8_t a : *iv )
        builder.AddCount(a);
    return std::move(builder).Build();
}

bool ParaglobVal::DoUnserializeData(BrokerDataView data) {
    if ( ! data.IsList() )
        return false;

    auto d = data.ToList();

    auto iv = std::make_unique<std::vector<uint8_t>>();
    iv->resize(d.Size());

    for ( size_t index = 0; index < d.Size(); ++index ) {
        if ( ! get_vector_idx_if_count(d, index, iv->data() + index) )
            return false;
    }

    try {
        this->internal_paraglob = std::make_unique<paraglob::Paraglob>(std::move(iv));
    } catch ( const paraglob::underflow_error& e ) {
        reporter->Error("Paraglob underflow error -> %s", e.what());
        return false;
    } catch ( const paraglob::overflow_error& e ) {
        reporter->Error("Paraglob overflow error -> %s", e.what());
        return false;
    }

    return true;
}

ValPtr ParaglobVal::DoClone(CloneState* state) {
    try {
        return make_intrusive<ParaglobVal>(std::make_unique<paraglob::Paraglob>(this->internal_paraglob->serialize()));
    } catch ( const paraglob::underflow_error& e ) {
        reporter->Error("Paraglob underflow error while cloning -> %s", e.what());
        return nullptr;
    } catch ( const paraglob::overflow_error& e ) {
        reporter->Error("Paraglob overflow error while cloning -> %s", e.what());
        return nullptr;
    }
}

} // namespace zeek
