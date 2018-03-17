// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_X509_H
#define FILE_ANALYSIS_X509_H

#include <string>

#include "Val.h"
#include "X509Common.h"

#if (OPENSSL_VERSION_NUMBER < 0x10002000L || LIBRESSL_VERSION_NUMBER)

#define X509_get_signature_nid(x) OBJ_obj2nid((x)->sig_alg->algorithm)

#endif

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || LIBRESSL_VERSION_NUMBER)

#define X509_OBJECT_new()   (X509_OBJECT*)malloc(sizeof(X509_OBJECT))
#define X509_OBJECT_free(a) free(a)

#define OCSP_SINGLERESP_get0_id(s) (s)->certId
#define OCSP_resp_get0_certs(x)    (x)->certs

#define EVP_PKEY_get0_DSA(p)    ((p)->pkey.dsa)
#define EVP_PKEY_get0_EC_KEY(p) ((p)->pkey.ec)
#define EVP_PKEY_get0_RSA(p)    ((p)->pkey.rsa)

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

namespace file_analysis {

class X509Val;

class X509 : public file_analysis::X509Common {
public:
	bool DeliverStream(const u_char* data, uint64 len) override;
	bool Undelivered(uint64 offset, uint64 len) override;
	bool EndOfFile() override;

	/**
	 * Converts an X509 certificate into a \c X509::Certificate record
	 * value. This is a static function that can be called from external,
	 * it doesn't depend on the state of any particular file analyzer.
	 *
	 * @param cert_val The certificate to converts.
	 *
	 * @param fid A file ID associated with the certificate, if any
	 * (primarily for error reporting).
	 *
	 * @param Returns the new record value and passes ownership to
	 * caller.
	 */
	static RecordVal* ParseCertificate(X509Val* cert_val, const char* fid = 0);

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return new X509(args, file); }

protected:
	X509(RecordVal* args, File* file);

private:
	void ParseBasicConstraints(X509_EXTENSION* ex);
	void ParseSAN(X509_EXTENSION* ex);
	void ParseExtensionsSpecific(X509_EXTENSION* ex, bool, ASN1_OBJECT*, const char*) override;

	std::string cert_data;

	// Helpers for ParseCertificate.
	static StringVal* KeyCurve(EVP_PKEY *key);
	static unsigned int KeyLength(EVP_PKEY *key);
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

private:
	::X509* certificate; // the wrapped certificate

	DECLARE_SERIAL(X509Val);
};

}

#endif
