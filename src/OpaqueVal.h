// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "IntrusivePtr.h"
#include "RandTest.h"
#include "Val.h"
#include "digest.h"
#include "paraglob/paraglob.h"

#include <broker/expected.hh>

#include <sys/types.h> // for u_char

namespace broker { class data; }
class OpaqueVal;

/**
  * Singleton that registers all available all available types of opaque
  * values. This faciliates their serialization into Broker values.
  */
class OpaqueMgr {
public:
	using Factory = IntrusivePtr<OpaqueVal> ();

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
	IntrusivePtr<OpaqueVal> Instantiate(const std::string& id) const;

	/** Returns the global manager singleton object. */
	static OpaqueMgr* mgr();

	/**
	 * Internal helper class to register an OpaqueVal-derived classes
	 * with the manager.
	 */
	template<class T>
	class Register {
	public:
		Register(const char* id)
			{ OpaqueMgr::mgr()->_types.emplace(id, &T::OpaqueInstantiate); }
	};

private:
	std::unordered_map<std::string, Factory*> _types;
};

/** Macro to insert into an OpaqueVal-derived class's declaration. */
#define DECLARE_OPAQUE_VALUE(T)                            \
    friend class OpaqueMgr::Register<T>;                   \
    friend IntrusivePtr<T> make_intrusive<T>();            \
    broker::expected<broker::data> DoSerialize() const override;             \
    bool DoUnserialize(const broker::data& data) override; \
    const char* OpaqueName() const override { return #T; } \
    static IntrusivePtr<OpaqueVal> OpaqueInstantiate() { return make_intrusive<T>(); }

#define __OPAQUE_MERGE(a, b) a ## b
#define __OPAQUE_ID(x) __OPAQUE_MERGE(_opaque, x)

/** Macro to insert into an OpaqueVal-derived class's implementation file. */
#define IMPLEMENT_OPAQUE_VALUE(T) static OpaqueMgr::Register<T> __OPAQUE_ID(__LINE__)(#T);

/**
 * Base class for all opaque values. Opaque values are types that are managed
 * completely internally, with no further script-level operators provided
 * (other than bif functions). See OpaqueVal.h for derived classes.
 */
class OpaqueVal : public Val {
public:
	[[deprecated("Remove in v4.1.  Construct from IntrusivePtr instead.")]]
	explicit OpaqueVal(OpaqueType* t);
	explicit OpaqueVal(IntrusivePtr<OpaqueType> t);
	~OpaqueVal() override;

	/**
	 * Serializes the value into a Broker representation.
	 *
	 * @return the broker representation, or an error if serialization
	 * isn't supported or failed.
	 */
	broker::expected<broker::data> Serialize() const;

	/**
	 * Reinstantiates a value from its serialized Broker representation.
	 *
	 * @param data Broker representation as returned by *Serialize()*.
	 * @return unserialized instances with reference count at +1
	 */
	static IntrusivePtr<OpaqueVal> Unserialize(const broker::data& data);

protected:
	friend class Val;
	friend class OpaqueMgr;
	OpaqueVal() { }

	/**
	 * Must be overridden to provide a serialized version of the derived
	 * class' state.
	 *
	 * @return the serialized data or an error if serialization
	 * isn't supported or failed.
	 */
	virtual broker::expected<broker::data> DoSerialize() const = 0;

	/**
	 * Must be overridden to recreate the the derived class' state from a
	 * serialization.
	 *
	 * @return true if successful.
	 */
	virtual bool DoUnserialize(const broker::data& data) = 0;

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
	IntrusivePtr<Val> DoClone(CloneState* state) override;

	/**
	 * Helper function for derived class that need to record a type
	 * during serialization.
	 */
	static broker::expected<broker::data> SerializeType(const IntrusivePtr<BroType>& t);

	/**
	 * Helper function for derived class that need to restore a type
	 * during unserialization. Returns the type at reference count +1.
	 */
	static IntrusivePtr<BroType> UnserializeType(const broker::data& data);
};

namespace probabilistic {
	class BloomFilter;
	class CardinalityCounter;
}

class HashVal : public OpaqueVal {
public:
	template <class T>
	static void digest_all(HashAlgorithm alg, const T& vlist, u_char* result)
		{
		auto h = hash_init(alg);

		for ( const auto& v : vlist )
			digest_one(h, v);

		hash_final(h, result);
		}

	bool IsValid() const;
	bool Init();
	bool Feed(const void* data, size_t size);
	IntrusivePtr<StringVal> Get();

protected:
	static void digest_one(EVP_MD_CTX* h, const Val* v);
	static void digest_one(EVP_MD_CTX* h, const IntrusivePtr<Val>& v);

	HashVal()	{ valid = false; }

	[[deprecated("Remove in v4.1. Construct from IntrusivePtr instead.")]]
	explicit HashVal(OpaqueType* t);
	explicit HashVal(IntrusivePtr<OpaqueType> t);

	virtual bool DoInit();
	virtual bool DoFeed(const void* data, size_t size);
	virtual IntrusivePtr<StringVal> DoGet();

private:
	// This flag exists because Get() can only be called once.
	bool valid;
};

class MD5Val : public HashVal {
public:
	template <class T>
	static void digest(const T& vlist, u_char result[MD5_DIGEST_LENGTH])
		{ digest_all(Hash_MD5, vlist, result); }

	template <class T>
	static void hmac(const T& vlist,
	                 u_char key[MD5_DIGEST_LENGTH],
	                 u_char result[MD5_DIGEST_LENGTH])
		{
		digest(vlist, result);

		for ( int i = 0; i < MD5_DIGEST_LENGTH; ++i )
			result[i] ^= key[i];

		internal_md5(result, MD5_DIGEST_LENGTH, result);
		}

	MD5Val();
	~MD5Val();

	IntrusivePtr<Val> DoClone(CloneState* state) override;

protected:
	friend class Val;

	bool DoInit() override;
	bool DoFeed(const void* data, size_t size) override;
	IntrusivePtr<StringVal> DoGet() override;

	DECLARE_OPAQUE_VALUE(MD5Val)
private:
	EVP_MD_CTX* ctx;
};

class SHA1Val : public HashVal {
public:
	template <class T>
	static void digest(const T& vlist, u_char result[SHA_DIGEST_LENGTH])
		{ digest_all(Hash_SHA1, vlist, result); }

	SHA1Val();
	~SHA1Val();

	IntrusivePtr<Val> DoClone(CloneState* state) override;

protected:
	friend class Val;

	bool DoInit() override;
	bool DoFeed(const void* data, size_t size) override;
	IntrusivePtr<StringVal> DoGet() override;

	DECLARE_OPAQUE_VALUE(SHA1Val)
private:
	EVP_MD_CTX* ctx;
};

class SHA256Val : public HashVal {
public:
	template <class T>
	static void digest(const T& vlist, u_char result[SHA256_DIGEST_LENGTH])
		{ digest_all(Hash_SHA256, vlist, result); }

	SHA256Val();
	~SHA256Val();

	IntrusivePtr<Val> DoClone(CloneState* state) override;

protected:
	friend class Val;

	bool DoInit() override;
	bool DoFeed(const void* data, size_t size) override;
	IntrusivePtr<StringVal> DoGet() override;

	DECLARE_OPAQUE_VALUE(SHA256Val)
private:
	EVP_MD_CTX* ctx;
};

class EntropyVal : public OpaqueVal {
public:
	EntropyVal();

	bool Feed(const void* data, size_t size);
	bool Get(double *r_ent, double *r_chisq, double *r_mean,
		 double *r_montepicalc, double *r_scc);

protected:
	friend class Val;

	DECLARE_OPAQUE_VALUE(EntropyVal)
private:
	RandTest state;
};

class BloomFilterVal : public OpaqueVal {
public:
	explicit BloomFilterVal(probabilistic::BloomFilter* bf);
	~BloomFilterVal() override;

	IntrusivePtr<Val> DoClone(CloneState* state) override;

	const IntrusivePtr<BroType>& Type() const
		{ return type; }

	bool Typify(IntrusivePtr<BroType> type);

	void Add(const Val* val);
	size_t Count(const Val* val) const;
	void Clear();
	bool Empty() const;
	std::string InternalState() const;

	static IntrusivePtr<BloomFilterVal> Merge(const BloomFilterVal* x,
	                                          const BloomFilterVal* y);

protected:
	friend class Val;
	BloomFilterVal();

	DECLARE_OPAQUE_VALUE(BloomFilterVal)
private:
	// Disable.
	BloomFilterVal(const BloomFilterVal&);
	BloomFilterVal& operator=(const BloomFilterVal&);

	IntrusivePtr<BroType> type;
	CompositeHash* hash;
	probabilistic::BloomFilter* bloom_filter;
};


class CardinalityVal: public OpaqueVal {
public:
	explicit CardinalityVal(probabilistic::CardinalityCounter*);
	~CardinalityVal() override;

	IntrusivePtr<Val> DoClone(CloneState* state) override;

	void Add(const Val* val);

	const IntrusivePtr<BroType>& Type() const
		{ return type; }

	bool Typify(IntrusivePtr<BroType> type);

	probabilistic::CardinalityCounter* Get()	{ return c; };

protected:
	CardinalityVal();

	DECLARE_OPAQUE_VALUE(CardinalityVal)
private:
	IntrusivePtr<BroType> type;
	CompositeHash* hash;
	probabilistic::CardinalityCounter* c;
};

class ParaglobVal : public OpaqueVal {
public:
	explicit ParaglobVal(std::unique_ptr<paraglob::Paraglob> p);
	IntrusivePtr<VectorVal> Get(StringVal* &pattern);
	IntrusivePtr<Val> DoClone(CloneState* state) override;
	bool operator==(const ParaglobVal& other) const;

protected:
	ParaglobVal() : OpaqueVal(paraglob_type) {}

	DECLARE_OPAQUE_VALUE(ParaglobVal)

private:
	std::unique_ptr<paraglob::Paraglob> internal_paraglob;
};
