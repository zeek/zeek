// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <map>

#include "zeek/OpaqueVal.h"
#include "zeek/file_analysis/analyzer/x509/X509Common.h"
#include "zeek/Func.h"

#if ( OPENSSL_VERSION_NUMBER < 0x10002000L ) || defined(LIBRESSL_VERSION_NUMBER)

#define X509_get_signature_nid(x) OBJ_obj2nid((x)->sig_alg->algorithm)

#endif

#if ( OPENSSL_VERSION_NUMBER < 0x1010000fL ) || defined(LIBRESSL_VERSION_NUMBER)

#define X509_OBJECT_new()   (X509_OBJECT*)malloc(sizeof(X509_OBJECT))
#define X509_OBJECT_free(a) free(a)

#define OCSP_resp_get0_certs(x)    (x)->certs

#define EVP_PKEY_get0_DSA(p)    ((p)->pkey.dsa)
#define EVP_PKEY_get0_EC_KEY(p) ((p)->pkey.ec)
#define EVP_PKEY_get0_RSA(p)    ((p)->pkey.rsa)

#if !defined(LIBRESSL_VERSION_NUMBER) || ( LIBRESSL_VERSION_NUMBER < 0x2070000fL )

#define OCSP_SINGLERESP_get0_id(s) (s)->certId

static X509 *X509_OBJECT_get0_X509(const X509_OBJECT *a)
{
	if ( a == nullptr || a->type != X509_LU_X509 )
		return nullptr;
	return a->data.x509;
}

static void DSA_get0_pqg(const DSA *d,
			 const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
	if ( p != nullptr )
		*p = d->p;
	if ( q != nullptr )
		*q = d->q;
	if ( g != nullptr )
		*g = d->g;
}

static void RSA_get0_key(const RSA *r,
			 const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
	if ( n != nullptr )
		*n = r->n;
	if ( e != nullptr )
		*e = r->e;
	if ( d != nullptr )
		*d = r->d;
}

#endif

#endif

namespace zeek::file_analysis::detail {

class X509Val;

class X509 : public file_analysis::detail::X509Common {
public:
	bool DeliverStream(const u_char* data, uint64_t len) override;
	bool Undelivered(uint64_t offset, uint64_t len) override;
	bool EndOfFile() override;

	/**
	 * Converts an X509 certificate into a \c X509::Certificate record
	 * value. This is a static function that can be called from external,
	 * it doesn't depend on the state of any particular file analyzer.
	 *
	 * @param cert_val The certificate to converts.
	 *
	 * @param f A file associated with the certificate, if any
	 * (primarily for error reporting).
	 *
	 * @param Returns the new record value and passes ownership to
	 * caller.
	 */
	static RecordValPtr ParseCertificate(X509Val* cert_val, file_analysis::File* file = nullptr);

	static file_analysis::Analyzer* Instantiate(RecordValPtr args,
	                                            file_analysis::File* file)
		{ return new X509(std::move(args), file); }

	/**
	 * Retrieves OpenSSL's representation of an X509 certificate store
	 * associated with a script-layer certificate root table variable/value.
	 * The underlying X509 store will be created if it has not been already,
	 * else the previously allocated one for the same table will be returned.
	 *
	 * @param root_certs  The script-layer certificate root table value.
	 *
	 * @return OpenSSL's X509 store associated with the table value.
	 */
	static X509_STORE* GetRootStore(TableVal* root_certs);

	/**
	 * Frees memory obtained from OpenSSL that is associated with the global
	 * X509 certificate store used by the Zeek scripting-layer.  This primarily
	 * exists so leak checkers like LeakSanitizer don't count the
	 * globally-allocated mapping as a leak.  Would be easy to suppress/ignore
	 * it, but that could accidentally silence cases where some new code
	 * mistakenly overwrites a table element without freeing it.
	 */
	static void FreeRootStore();

	/**
	 * Sets the table[string] that used as the certificate cache inside of Zeek.
	 */
	static void SetCertificateCache(TableValPtr cache)
		{ certificate_cache = std::move(cache); }

	/**
	 * Sets the callback when a certificate cache hit is encountered
	 */
	static void SetCertificateCacheHitCallback(FuncPtr func)
		{ cache_hit_callback = std::move(func); }

protected:
	X509(RecordValPtr args, file_analysis::File* file);

private:
	void ParseBasicConstraints(X509_EXTENSION* ex);
	void ParseSAN(X509_EXTENSION* ex);
	void ParseExtensionsSpecific(X509_EXTENSION* ex, bool, ASN1_OBJECT*, const char*) override;

	std::string cert_data;

	// Helpers for ParseCertificate.
	static StringValPtr KeyCurve(EVP_PKEY* key);
	static unsigned int KeyLength(EVP_PKEY *key);
	/** X509 stores associated with global script-layer values */
	inline static std::map<Val*, X509_STORE*> x509_stores = std::map<Val*, X509_STORE*>();
	inline static TableValPtr certificate_cache = nullptr;
	inline static FuncPtr cache_hit_callback = nullptr;
};

/**
 * This class wraps an OpenSSL X509 data structure.
 *
 * We need these to be able to pass OpenSSL pointers around in Bro
 * script-land. Otherwise, we cannot verify certificates from Bro
 * scriptland
 */
class X509Val : public OpaqueVal {
public:
	/**
	 * Construct an X509Val.
	 *
	 * @param certificate specifies the wrapped OpenSSL certificate
	 *
	 * @return A newly initialized X509Val.
	 */
	explicit X509Val(::X509* certificate);

	/**
	 * Clone an X509Val
	 *
	 * @param state certifies the state of the clone operation (duplicate tracking)
	 *
	 * @return A cloned X509Val.
	 */
	ValPtr DoClone(CloneState* state) override;

	/**
	 * Destructor.
	 */
	~X509Val() override;

	/**
	 * Get the wrapped X509 certificate. Please take care, that the
	 * internal OpenSSL reference counting stays the same.
	 *
	 * @return The wrapped OpenSSL X509 certificate.
	 */
	::X509* GetCertificate() const;

protected:
	/**
	 * Construct an empty X509Val. Only used for deserialization
	 */
	X509Val();

	DECLARE_OPAQUE_VALUE(X509Val)
private:
	::X509* certificate; // the wrapped certificate
};

} // namespace zeek::file_analysis::detail
