// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_X509_H
#define FILE_ANALYSIS_X509_H

#include <string>

#include "Val.h"
#include "../File.h"
#include "Analyzer.h"

#include <openssl/x509.h>
#include <openssl/asn1.h>

namespace file_analysis {

class X509Val;

class X509 : public file_analysis::Analyzer {
public:
	virtual bool DeliverStream(const u_char* data, uint64 len);
	virtual bool Undelivered(uint64 offset, uint64 len);
	virtual bool EndOfFile();

	/**
	 * Converts an X509 certificate into a \c X509::Certificate record
	 * value. This is a static function that can be called from external,
	 * it doesn't depend on the state of any particular file analyzer.
	 *
	 * @param cert_val The certificate to converts.
	 *
	 * @param Returns the new record value and passes ownership to
	 * caller.
	 */
	static RecordVal* ParseCertificate(X509Val* cert_val);

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return new X509(args, file); }

protected:
	X509(RecordVal* args, File* file);

private:
	void ParseExtension(X509_EXTENSION* ex);
	void ParseBasicConstraints(X509_EXTENSION* ex);
	void ParseSAN(X509_EXTENSION* ex);

	std::string cert_data;

	// Helpers for ParseCertificate.
	static double GetTimeFromAsn1(const ASN1_TIME * atime);
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
	~X509Val();

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
