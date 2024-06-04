// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#ifdef _MSC_VER
#include <unistd.h>
#endif

#include <broker/expected.hh>
#include <paraglob/paraglob.h>
#include <sys/types.h> // for u_char
#include <optional>

#include "zeek/IntrusivePtr.h"
#include "zeek/RandTest.h"
#include "zeek/Val.h"
#include "zeek/digest.h"
#include "zeek/telemetry/Counter.h"
#include "zeek/telemetry/Gauge.h"
#include "zeek/telemetry/Histogram.h"

namespace broker {
class data;
}

namespace zeek {

class BrokerData;
class BrokerDataView;
class BrokerListView;

namespace probabilistic {
class BloomFilter;
}
namespace probabilistic::detail {
class CardinalityCounter;
}

class OpaqueVal;
using OpaqueValPtr = IntrusivePtr<OpaqueVal>;

class BloomFilterVal;
using BloomFilterValPtr = IntrusivePtr<BloomFilterVal>;

/**
 * Singleton that registers all available all available types of opaque
 * values. This facilitates their serialization into Broker values.
 */
class OpaqueMgr {
public:
    using Factory = OpaqueValPtr();

    /**
     * Return's a unique ID for the type of an opaque value.
     * @param v opaque value to return type for; its class must have been
     * registered with the manager, otherwise this method will abort
     * execution.
     *
     * @return type ID, which can used with *Instantiate()* to create a
     * new instance of the same type.
     */
    const std::string& TypeID(const OpaqueVal* v) const;

    /**
     * Instantiates a new opaque value of a specific opaque type.
     *
     * @param id unique type ID for the class to instantiate; this will
     * normally have been returned earlier by *TypeID()*.
     *
     * @return A freshly instantiated value of the OpaqueVal-derived
     * classes that *id* specifies, with reference count at +1. If *id*
     * is unknown, this will return null.
     *
     */
    OpaqueValPtr Instantiate(const std::string& id) const;

    /** Returns the global manager singleton object. */
    static OpaqueMgr* mgr();

    /**
     * Internal helper class to register an OpaqueVal-derived classes
     * with the manager.
     */
    template<class T>
    class Register {
    public:
        Register(const char* id) { OpaqueMgr::mgr()->_types.emplace(id, &T::OpaqueInstantiate); }
    };

private:
    std::unordered_map<std::string, Factory*> _types;
};

/**
 * Legacy macro to insert into an OpaqueVal-derived class's declaration. Overrides the "old" serialization methods
 * DoSerialize and DoUnserialize.
 * @deprecated Use DECLARE_OPAQUE_VALUE_DATA instead. Remove in v7.1.
 */
#define DECLARE_OPAQUE_VALUE(T)                                                                                        \
    friend class zeek::OpaqueMgr::Register<T>;                                                                         \
    friend zeek::IntrusivePtr<T> zeek::make_intrusive<T>();                                                            \
    broker::expected<broker::data> DoSerialize() const override;                                                       \
    bool DoUnserialize(const broker::data& data) override;                                                             \
    const char* OpaqueName() const override { return #T; }                                                             \
    static zeek::OpaqueValPtr OpaqueInstantiate() { return zeek::make_intrusive<T>(); }

/**
 * Macro to insert into an OpaqueVal-derived class's declaration. Overrides the "new" serialization methods
 * DoSerializeData and DoUnserializeData.
 */
#define DECLARE_OPAQUE_VALUE_DATA(T)                                                                                   \
    friend class zeek::OpaqueMgr::Register<T>;                                                                         \
    friend zeek::IntrusivePtr<T> zeek::make_intrusive<T>();                                                            \
    std::optional<zeek::BrokerData> DoSerializeData() const override;                                                  \
    bool DoUnserializeData(zeek::BrokerDataView data) override;                                                        \
    const char* OpaqueName() const override { return #T; }                                                             \
    static zeek::OpaqueValPtr OpaqueInstantiate() { return zeek::make_intrusive<T>(); }

#define __OPAQUE_MERGE(a, b) a##b
#define __OPAQUE_ID(x) __OPAQUE_MERGE(_opaque, x)

/** Macro to insert into an OpaqueVal-derived class's implementation file. */
#define IMPLEMENT_OPAQUE_VALUE(T) static zeek::OpaqueMgr::Register<T> __OPAQUE_ID(__LINE__)(#T);

/**
 * Base class for all opaque values. Opaque values are types that are managed
 * completely internally, with no further script-level operators provided
 * (other than bif functions). See OpaqueVal.h for derived classes.
 */
class OpaqueVal : public Val {
public:
    explicit OpaqueVal(OpaqueTypePtr t);
    ~OpaqueVal() override = default;

    /**
     * Serializes the value into a Broker representation.
     *
     * @return the broker representation, or an error if serialization
     * isn't supported or failed.
     */
    [[deprecated("Remove in v7.1: use SerializeData instead")]] broker::expected<broker::data> Serialize() const;

    /**
     * @copydoc Serialize
     */
    std::optional<BrokerData> SerializeData() const;

    /**
     * Reinstantiates a value from its serialized Broker representation.
     *
     * @param data Broker representation as returned by *Serialize()*.
     * @return unserialized instances with reference count at +1
     */
    [[deprecated("Remove in v7.1: use UnserializeData instead")]] static OpaqueValPtr Unserialize(
        const broker::data& data);

    /**
     * @copydoc Unserialize
     */
    static OpaqueValPtr UnserializeData(BrokerDataView data);

    /**
     * @copydoc Unserialize
     */
    static OpaqueValPtr UnserializeData(BrokerListView data);

protected:
    friend class Val;
    friend class OpaqueMgr;

    /**
     * @deprecated Override DoSerializeData instead. Remove in v7.1.
     */
    virtual broker::expected<broker::data> DoSerialize() const;

    /**
     * Must be overridden to provide a serialized version of the derived
     * class' state.
     *
     * @return the serialized data or an error if serialization
     * isn't supported or failed.
     */
    virtual std::optional<BrokerData> DoSerializeData() const;

    /**
     * @deprecated Override DoUnserializeData instead. Remove in v7.1.
     */
    virtual bool DoUnserialize(const broker::data& data);

    /**
     * Must be overridden to recreate the derived class' state from a
     * serialization.
     *
     * @return true if successful.
     */
    virtual bool DoUnserializeData(BrokerDataView data);

    /**
     * Internal helper for the serialization machinery. Automatically
     * overridden by the `DECLARE_OPAQUE_VALUE` macro.
     */
    virtual const char* OpaqueName() const = 0;

    /**
     * Provides an implementation of *Val::DoClone()* that leverages the
     * serialization methods to deep-copy an instance. Derived classes
     * may also override this with a more efficient custom clone
     * implementation of their own.
     */
    ValPtr DoClone(CloneState* state) override;

    /**
     * Helper function for derived class that need to record a type
     * during serialization.
     */
    static std::optional<BrokerData> SerializeType(const TypePtr& t);

    /**
     * Helper function for derived class that need to restore a type
     * during unserialization. Returns the type at reference count +1.
     */
    static TypePtr UnserializeType(BrokerDataView data);

    void ValDescribe(ODesc* d) const override;
    void ValDescribeReST(ODesc* d) const override;
};

class HashVal : public OpaqueVal {
public:
    template<class T>
    static void digest_all(detail::HashAlgorithm alg, const T& vlist, u_char* result) {
        auto h = detail::hash_init(alg);

        for ( const auto& v : vlist )
            digest_one(h, v);

        detail::hash_final(h, result);
    }

    bool IsValid() const;
    bool Init();
    bool Feed(const void* data, size_t size);
    StringValPtr Get();

protected:
    static void digest_one(detail::HashDigestState* h, const Val* v);
    static void digest_one(detail::HashDigestState* h, const ValPtr& v);

    explicit HashVal(OpaqueTypePtr t);

    virtual bool DoInit();
    virtual bool DoFeed(const void* data, size_t size);
    virtual StringValPtr DoGet();

private:
    // This flag exists because Get() can only be called once.
    bool valid;
};

class MD5Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_MD5_DIGEST_LENGTH]) {
        digest_all(detail::Hash_MD5, vlist, result);
    }

    template<class T>
    static void hmac(const T& vlist, u_char key[ZEEK_MD5_DIGEST_LENGTH], u_char result[ZEEK_MD5_DIGEST_LENGTH]) {
        digest(vlist, result);

        for ( int i = 0; i < ZEEK_MD5_DIGEST_LENGTH; ++i )
            result[i] ^= key[i];

        detail::internal_md5(result, ZEEK_MD5_DIGEST_LENGTH, result);
    }

    MD5Val();
    ~MD5Val();

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(MD5Val)
private:
    StatePtr ctx = nullptr;
};

class SHA1Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_SHA_DIGEST_LENGTH]) {
        digest_all(detail::Hash_SHA1, vlist, result);
    }

    SHA1Val();
    ~SHA1Val();

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(SHA1Val)
private:
    StatePtr ctx = nullptr;
};

class SHA256Val : public HashVal {
public:
    struct State;

    using StatePtr = State*;

    template<class T>
    static void digest(const T& vlist, u_char result[ZEEK_SHA256_DIGEST_LENGTH]) {
        digest_all(detail::Hash_SHA256, vlist, result);
    }

    SHA256Val();
    ~SHA256Val();

    ValPtr DoClone(CloneState* state) override;

protected:
    friend class Val;

    bool DoInit() override;
    bool DoFeed(const void* data, size_t size) override;
    StringValPtr DoGet() override;

    DECLARE_OPAQUE_VALUE_DATA(SHA256Val)
private:
    StatePtr ctx = nullptr;
};

class EntropyVal : public OpaqueVal {
public:
    EntropyVal();

    bool Feed(const void* data, size_t size);
    bool Get(double* r_ent, double* r_chisq, double* r_mean, double* r_montepicalc, double* r_scc);

protected:
    friend class Val;

    DECLARE_OPAQUE_VALUE_DATA(EntropyVal)
private:
    detail::RandTest state;
};

class BloomFilterVal : public OpaqueVal {
public:
    explicit BloomFilterVal(probabilistic::BloomFilter* bf);
    ~BloomFilterVal() override;

    ValPtr DoClone(CloneState* state) override;

    const TypePtr& Type() const { return type; }

    bool Typify(TypePtr type);

    void Add(const Val* val);
    bool Decrement(const Val* val);
    size_t Count(const Val* val) const;
    void Clear();
    bool Empty() const;
    std::string InternalState() const;

    static BloomFilterValPtr Merge(const BloomFilterVal* x, const BloomFilterVal* y);
    static BloomFilterValPtr Intersect(const BloomFilterVal* x, const BloomFilterVal* y);

protected:
    friend class Val;
    BloomFilterVal();

    DECLARE_OPAQUE_VALUE_DATA(BloomFilterVal)
private:
    // Disable.
    BloomFilterVal(const BloomFilterVal&);
    BloomFilterVal& operator=(const BloomFilterVal&);

    TypePtr type;
    detail::CompositeHash* hash;
    probabilistic::BloomFilter* bloom_filter;
};

class CardinalityVal : public OpaqueVal {
public:
    explicit CardinalityVal(probabilistic::detail::CardinalityCounter*);
    ~CardinalityVal() override;

    ValPtr DoClone(CloneState* state) override;

    void Add(const Val* val);

    const TypePtr& Type() const { return type; }

    bool Typify(TypePtr type);

    probabilistic::detail::CardinalityCounter* Get() { return c; };

protected:
    CardinalityVal();

    DECLARE_OPAQUE_VALUE_DATA(CardinalityVal)
private:
    TypePtr type;
    detail::CompositeHash* hash;
    probabilistic::detail::CardinalityCounter* c;
};

class ParaglobVal : public OpaqueVal {
public:
    explicit ParaglobVal(std::unique_ptr<paraglob::Paraglob> p);
    VectorValPtr Get(StringVal*& pattern);
    ValPtr DoClone(CloneState* state) override;
    bool operator==(const ParaglobVal& other) const;

protected:
    ParaglobVal() : OpaqueVal(paraglob_type) {}

    DECLARE_OPAQUE_VALUE_DATA(ParaglobVal)

private:
    std::unique_ptr<paraglob::Paraglob> internal_paraglob;
};

} // namespace zeek
