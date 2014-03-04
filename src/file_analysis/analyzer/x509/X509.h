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
	//~X509();

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return new X509(args, file); }
	
	static RecordVal* ParseCertificate(X509Val* cert_val);

	virtual bool DeliverStream(const u_char* data, uint64 len);
	virtual bool Undelivered(uint64 offset, uint64 len);	
	virtual bool EndOfFile();

protected:
	X509(RecordVal* args, File* file);

private:
	static double get_time_from_asn1(const ASN1_TIME * atime);
	static StringVal* key_curve(EVP_PKEY *key);
	static unsigned int key_length(EVP_PKEY *key);

	void ParseExtension(X509_EXTENSION* ex);
	void ParseBasicConstraints(X509_EXTENSION* ex);
	void ParseSAN(X509_EXTENSION* ex);

	std::string cert_data;
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
	 * @return A newly initialized X509Val
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
	 * @return The wrapped OpenSSL X509 certificate
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
